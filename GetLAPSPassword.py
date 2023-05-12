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
#   This script will gather data about the domain's computers and their LAPS passwords.
#     Initial formatting for this tool came from the GetADUsers.py example script.
#
# Author:
#   Tyler Booth (@dru1d-foofus)
#
# Reference for:
#   LDAP
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys
import os
from datetime import datetime

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError


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

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        # Let's calculate the header and format
        self.__header = ["Name", "LAPS Password", "LAPS Password Expiration"]
        self.__colLen = [20, 20, 30]
        self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])

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

            print((self.__outputFormat.format(*[cn, lapsPassword, lapsPasswordExpiration])))
        except Exception as e:
            logging.error('Error processing record: %s', str(e))
            logging.debug(item, exc_info=True)
            pass
        cn = "test"
        lapsPassword = "as13r34,234!dfa"
        lapsPasswordExpiration = '2023-06-08ASDF'
        output_line = self.__outputFormat.format(*[cn, lapsPassword, lapsPasswordExpiration])
        print(output_line)
        self.__write_to_file(output_line.replace(' ', '|'))  # Save the output to a PSV
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

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)
            # Search for computer objects and include the 'ms-MCS-AdmPwdExpirationTime' attribute
            laps_enabled = ldapConnection.search(searchFilter=searchFilter,
                                  attributes=['cn', 'ms-MCS-AdmPwd', 'ms-MCS-AdmPwdExpirationTime'],
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