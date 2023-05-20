#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will gather data about the domain's computers and their LAPS/LAPSv2 passwords.
#     Initial formatting for this tool came from the GetADUsers.py example script.
#
# Author(s):
#   Thomas Seigneuret (@zblurx)
#   Tyler Booth (@dru1d-foofus)
#
# Reference for:
#   LDAP
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from datetime import datetime
from impacket import version
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.dpapi_ng import EncryptedPasswordBlob, KeyIdentifier, compute_kek, create_sd, decrypt_plaintext, unwrap_cek
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652
import argparse
import json
import logging
import os
import sys


class GetLAPSPassword:
    def __init__(self, username, password, domain, cmdLineOptions, output_file=None):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        #[!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__targetComputer = cmdLineOptions.computer
        self.__allComputers = cmdLineOptions.all_computers
        self.__lapsv2 = cmdLineOptions.lapsv2

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        if self.__lapsv2:
            self.__header = ["Name", "LAPS Username", "LAPS Password", "LAPS Password Expiration"]
            self.__colLen = [20, 20, 20, 30]
        else:
            self.__header = ["Name", "LAPS Password", "LAPS Password Expiration"]
            self.__colLen = [20, 20, 30]

        self.__outputFormat = '| '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])

        # Output file magic
        self.__output_file = output_file

        # If output_file is provided, open it in write mode
        if self.__output_file:
            self.__file = open(self.__output_file, 'w')
    
    def __write_to_file(self, data):
        if self.__output_file:
            self.__file.write(data + '\n')

    def test_output_file(self):
        if not self.__output_file:
            print("No output file specified.")
            return

        # Generate sample data
        sample_data = [
            ("Computer1", "SamplePassword1", "2023-05-15 13:23:00"),
            ("Computer2", "SamplePassword2", "2023-06-10 08:45:30"),
        ]

        # Print and write sample data
        for data in sample_data:
            data_line = '|'.join(data)
            print(data_line)
            self.__write_to_file(data_line)

        print("Sample data written to the output file.")

    def finish(self):
        if self.__output_file:
            self.__file.close()

    def getMachineName(self, target):
        try:
            s = SMBConnection(target, target)
            s.login('', '')
        except OSError as e:
            if str(e).find('timed out') > 0:
                raise Exception('The connection is timed out. Probably 445/TCP port is closed. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except SessionError as e:
            if str(e).find('STATUS_NOT_SUPPORTED') > 0:
                raise Exception('The SMB request is not supported. Probably NTLM is disabled. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % target)
        else:
            s.logoff()
        return s.getServerName()

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def processRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        cn = 'N/A'
        lapsUsername = 'N/A'
        lapsPassword = 'N/A'
        lapsPasswordExpiration = 'N/A'
        laps_enabled = False
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'cn':
                    cn = attribute['vals'][0].asOctets().decode('utf-8')
                elif str(attribute['type']) == 'ms-Mcs-AdmPwdExpirationTime':
                    if str(attribute['vals'][0]) == '0':
                        lapsPasswordExpiration = 'N/A'
                    else:
                        lapsPasswordExpiration = datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))).strftime('%Y-%m-%d %H:%M:%S')
                elif str(attribute['type']) == 'ms-Mcs-AdmPwd':
                    lapsPassword = attribute['vals'][0].asOctets().decode('utf-8')
                    laps_enabled = True
                elif str(attribute['type']) == 'msLAPS-EncryptedPassword':  # Checking for msLAPS-EncryptedPassword
                    rawEncryptedLAPSBlob = bytes(attribute['vals'][0])
                    KDSCache = {}
                    try:
                        encryptedLAPSBlob = EncryptedPasswordBlob(rawEncryptedLAPSBlob)
                        parsed_cms_data, remaining = decoder.decode(encryptedLAPSBlob['Blob'], asn1Spec=rfc5652.ContentInfo())
                        enveloped_data_blob = parsed_cms_data['content']
                        parsed_enveloped_data, _ = decoder.decode(enveloped_data_blob, asn1Spec=rfc5652.EnvelopedData())

                        recipient_infos = parsed_enveloped_data['recipientInfos']
                        kek_recipient_info = recipient_infos[0]['kekri']
                        kek_identifier = kek_recipient_info['kekid'] 
                        key_id = KeyIdentifier(bytes(kek_identifier['keyIdentifier']))
                        tmp,_ = decoder.decode(kek_identifier['other']['keyAttr'])
                        sid = tmp['field-1'][0][0][1].asOctets().decode("utf-8") 
                        target_sd = create_sd(sid)
                        laps_enabled = True
                    except Exception as e:
                        logging.error('Cannot unpack msLAPS-EncryptedPassword blob due to error %s' % str(e))
                    # Check if item is in cache
                    if key_id['RootKeyId'] in KDSCache:
                        logging.debug("Got KDS from cache")
                        gke = KDSCache[key_id['RootKeyId']]
                    else:
                        # Connect on RPC over TCP to MS-GKDI to call opnum 0 GetKey 
                        stringBinding = hept_map(destHost=self.__target, remoteIf=MSRPC_UUID_GKDI, protocol = 'ncacn_ip_tcp')
                        rpctransport = transport.DCERPCTransportFactory(stringBinding)
                        if hasattr(rpctransport, 'set_credentials'):
                            rpctransport.set_credentials(username=self.__username, password=self.__password, domain=self.__domain, lmhash=self.__lmhash, nthash=self.__nthash)
                        if self.__doKerberos:
                            rpctransport.set_kerberos(self.__doKerberos, kdcHost=self.__target)
                        if self.__kdcIP is not None:
                            rpctransport.setRemoteHost(self.__kdcIP)
                            rpctransport.setRemoteName(self.__target)

                        dce = rpctransport.get_dce_rpc()
                        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
                        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                        logging.debug("Connecting to %s" % stringBinding)
                        try:
                            dce.connect()
                        except Exception as e:
                            logging.error("Something went wrong, check error status => %s" % str(e))
                            return laps_enabled
                        logging.debug("Connected")
                        try:
                            dce.bind(MSRPC_UUID_GKDI)
                        except Exception as e:
                            logging.error("Something went wrong, check error status => %s" % str(e))
                            return laps_enabled
                        logging.debug("Successfully bound")


                        logging.debug("Calling MS-GKDI GetKey")
                        resp = GkdiGetKey(dce, target_sd=target_sd, l0=key_id['L0Index'], l1=key_id['L1Index'], l2=key_id['L2Index'], root_key_id=key_id['RootKeyId'])
                        logging.debug("Decrypting password")
                        # Unpack GroupKeyEnvelope
                        gke = GroupKeyEnvelope(b''.join(resp['pbbOut']))
                        KDSCache[gke['RootKeyId']] = gke

                        kek = compute_kek(gke, key_id)
                        logging.debug("KEK:\t%s" % kek)
                        enc_content_parameter = bytes(parsed_enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
                        iv, _ = decoder.decode(enc_content_parameter)
                        iv = bytes(iv[0])

                        cek = unwrap_cek(kek, bytes(kek_recipient_info['encryptedKey']))
                        logging.debug("CEK:\t%s" % cek)
                        plaintext = decrypt_plaintext(cek, iv, remaining)

            if self.__lapsv2:
                json_str = plaintext[:-18].decode('utf-16le')
                json_obj = json.loads(json_str)  # parse JSON string into Python dictionary
                lapsUsername = json_obj.get('n', 'N/A')  # if 'n' key does not exist, 'N/A' is returned
                lapsPassword = json_obj.get('p', 'N/A')
                print(self.__outputFormat.format(*[cn, lapsUsername, lapsPassword, lapsPasswordExpiration]))
            else:
                print((self.__outputFormat.format(*[cn, lapsPassword, lapsPasswordExpiration])))
        except Exception as e:
            logging.error('Error processing record: %s', str(e))
            logging.debug(item, exc_info=True)
            pass
        if self.__lapsv2:
            output_line = self.__outputFormat.format(cn, lapsUsername, lapsPassword, lapsPasswordExpiration)
            self.__write_to_file(output_line.strip().replace(' ', ''))
        else:
            output_line = self.__outputFormat.format(cn, lapsPassword, lapsPasswordExpiration)
            self.__write_to_file(output_line.strip().replace(' ', ''))
        return laps_enabled


    def run(self):
        if self.__kdcHost is not None:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__domain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                         "must match exactly each other.")
                raise

        logging.info('Querying %s for information about domain.' % self.__target)
        # Print header
        print((self.__outputFormat.format(*self.__header)))
        print(('  '.join(['-' * itemLen for itemLen in self.__colLen])))

        # Building the search filter
        searchFilter = "(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationtime=*))"  # Default search filter value
        if self.__allComputers:
            pass  # Already set to the default value
        elif self.__targetComputer is not None:
            searchFilter = "(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationtime=*)(cn=%s))"
            searchFilter = searchFilter % self.__targetComputer
        elif self.__lapsv2:
            searchFilter = "(&(objectCategory=computer)(msLAPS-EncryptedPassword=*))"
        elif self.__lapsv2 and self.__targetComputer is not None:
            searchFilter = "(&(objectCategory=computer)(msLAPS-EncryptedPassword=*)(cn=%s))"
            searchFilter = searchFilter % self.__targetComputer

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)
            # Search for computer objects and include the 'ms-MCS-AdmPwdExpirationTime' attribute
            laps_enabled = ldapConnection.search(searchFilter=searchFilter,
                                  attributes=['cn', 'ms-MCS-AdmPwd', 'ms-MCS-AdmPwdExpirationTime', 'msLAPS-EncryptedPassword', 'msLAPS-Password', \
                                  'msLAPS-PasswordExpirationTime'],
                                  sizeLimit=0, searchControls = [sc], perRecordCallback=self.processRecord)
            if laps_enabled == False:
                print("\n[!] LAPS is not enabled for this domain.")

        except ldap.LDAPSearchError:
                raise

        ldapConnection.close()
        if self.__output_file:
            self.__file.close()

# Process command-line arguments.
if __name__ == '__main__':
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for users data")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-computer', action='store', metavar='computername', help='Target a specific computer by its name')
    parser.add_argument('-all-computers', action='store_true', help='Target all computers in the environment')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-outputfile', '-o', action='store', help='Outputs to a file.')
    parser.add_argument('-lapsv2', action='store_true', help='Toggles LAPS Version 2.0 extraction')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CcnAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    output_file = options.outputfile

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    try:
        executer = GetLAPSPassword(username, password, domain, options, output_file)
        executer.run()

        # Run the test function to create a sample output file; comment out the executor.run() above and uncomment
        # the line below.
        #executer.test_output_file()
        executer.finish()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))