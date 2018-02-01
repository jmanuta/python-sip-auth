#!/usr/bin/env python
# jmanuta@bluip.com | 2018.01.30
# Description:  SIP Client Password Check
#               This script will use a dictionary (line separated) to determine
#               what password was used by the client during digest
#               authentication.


import hashlib
import re
import sys


class AuthCheck(object):



    def __init__(self, dictionary_file):
        self.dictionary_file = dictionary_file
        self.capture_packet()
        self.parse_packet()
        self.find_match()


    def capture_packet(self):
        """ capture Authorization header
        """
        print("\nPaste Authorization header or full packet containing "
            "Authorization header. (Enter blank line to submit): \n")

        # Store each line of the packet in a list
        self.sip_packet = []
        while True:
            line = input()
            if line:
                self.sip_packet.append(line)
            else:
                break


    def parse_packet(self):
        """ Extract fields from Authorization header
        """

        # Store Authorization header in string
        if "authorization:" in "".join(self.sip_packet).lower():
            for line in self.sip_packet:
                if line.lower().startswith("authorization"):
                # List of values past "Authorization: Digest"
                    auth_header = (line.split()[2:])
                # Concatenate the list to string
                    auth_header = "".join(auth_header)
                # Remove double quotes if present
                    auth_header = auth_header.replace('"', '')
        else:
            print("Invalid SIP packet: Missing Authorization header")

        # Store Authorization fields in dictionary
        auth_dict = {}
        for item in auth_header.split(","):
            auth_dict[item.lower().split("=", 1)[0]] = item.split("=", 1)[1]

        # Store dictionary values in variables
        self.username = auth_dict['username']
        self.realm = auth_dict['realm']
        self.nonce = auth_dict['nonce']
        self.uri = auth_dict['uri']
        self.response = auth_dict['response']
        self.cnonce = auth_dict['cnonce']
        self.qop = auth_dict['qop']
        self.nc = auth_dict['nc']


    def calculate_ha1(self, password):
        """ MD5 hash of username:realm:password
        """
        combine = "{}:{}:{}".format(self.username, self.realm, password)
        ha1 = hashlib.md5(combine.encode('utf-8'))
        ha1 = ha1.hexdigest()
        print("ha1 done {}".format(ha1))
        return(ha1)

    def calculate_ha2(self, method):
        """ MD5 hash of method:uri
        """
        combine = "{}:{}".format(method, self.uri)
        ha2 = hashlib.md5(combine.encode('utf-8'))
        ha2 = ha2.hexdigest()
        print("ha2 done {}".format(ha2))
        return(ha2)

    def calculate_response(self, ha1, ha2):
        """ MD5 hash of ha1:nonce:nc:cnonce:auth:ha2
        """
        combine = "{}:{}:{}:{}:auth:{}".format(ha1, self.nonce, self.nc,
            self.cnonce, ha2)
        my_response = hashlib.md5(combine.encode('utf-8'))
        myresponse = my_response.hexdigest()
        return(myresponse)

    def verify_match(self, my_response, response):
        """ Check if responses match
        """
        my_response = str(my_response)
        response = str(response)
        if my_response == response:
            return(True)

        elif my_response != response:
            return(False)


    def find_match(self):
        """ Open dictionary and test each password listed
        """
        with open(self.dictionary_file, errors='ignore') as dict_file:
            match = False
            dict_file_content = dict_file.read()
            passwords = re.split('\n', dict_file_content)
            for password in passwords:
                ha1 = self.calculate_ha1(password)
                methods = ('INVITE')
                for method in methods:
                    ha2 = self.calculate_ha2(method)
                    my_response = self.calculate_response(ha1, ha2)
                    results = self.verify_match(my_response, self.response)
                    if results == True:
                        match = True
                        self.password = password
                        break
            if not match:
                return


if __name__ == '__main__':
    session = AuthCheck(sys.argv[1])
    if session.password:
        print(session.password)
    else:
        print("No Matches")
