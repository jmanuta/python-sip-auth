#!/usr/bin/env python
# jmanuta@bluip.com | 2018.01.30
# Description:  SIP Client Password Check
#               This script will use a password dictionary (line separated) to 
#               determine what password was used by the client during digest 
#               authentication.


import hashlib
import re
import sys


def capture_packet():
    """ capture Authorization header
    """
    print("\nPaste Authorization header or full packet containing "
        "Authorization header. (Enter blank line to submit): \n")

    # Store each line of the packet in a list
    lines = []
    while True:
        if sys.version_info[0] < 3:
            line = raw_input()
        else:
            line = input()
        if line:
            lines.append(line)
        else:
            break
    return(lines)


def parse_packet(sip_packet):
    """ Extract fields from Authorization header
    """
    # Store Authorization header in string
    if "authorization:" in "".join(sip_packet).lower():
        for line in sip_packet:
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
    username = auth_dict['username']
    realm = auth_dict['realm']
    nonce = auth_dict['nonce']
    uri = auth_dict['uri']
    response = auth_dict['response']
    cnonce = auth_dict['cnonce']
    qop = auth_dict['qop']
    nc = auth_dict['nc']


    return(username, realm, nonce, uri, response, cnonce, qop, nc)


def calculate_ha1(username, realm, password):
    """ MD5 hash of username:realm:password
    """
    combine = "{}:{}:{}".format(username, realm, password)
    ha1 = hashlib.md5(combine.encode('utf-8'))
    ha1 = ha1.hexdigest()
    # print("ha1 done {}".format(ha1))
    return(ha1)


def calculate_ha2(method, uri):
    """ MD5 hash of method:uri
    """
    combine = "{}:{}".format(method, uri)
    ha2 = hashlib.md5(combine.encode('utf-8'))
    ha2 = ha2.hexdigest()
    # print("ha2 done {}".format(ha2))
    return(ha2)


def calculate_response(ha1, nonce, nc, cnonce, ha2):
    """ MD5 hash of ha1:nonce:nc:cnonce:auth:ha2
    """
    combine = "{}:{}:{}:{}:auth:{}".format(ha1, nonce, nc, cnonce, ha2)
    my_response = hashlib.md5(combine.encode('utf-8'))
    return(my_response.hexdigest())


def verify_match(my_response, response):
    """ Check if responses match
    """
    my_response = str(my_response)
    response = str(response)
    if my_response == response:
        return(True)
    elif my_response != response:
        return(False)


def find_match(dictionary_file):
    """ Open dictionary and test each password listed
    """
    username, realm, nonce, uri, response, cnonce, \
        qop, nc = parse_packet(sip_packet)

    if sys.version_info[0] < 3:
        with open(dictionary_file) as dict_file:
            match = False
            dict_file_content = dict_file.read()
            passwords = re.split('\n', dict_file_content)
            for password in passwords:
                ha1 = calculate_ha1(username, realm, password)
                methods = ('INVITE', 'REGISTER', 'UPDATE', 'REFER')
                for method in methods:
                    ha2 = calculate_ha2(method, uri)
                    my_response = calculate_response(ha1, nonce, nc, cnonce, ha2)
                    results = verify_match(my_response, response)
                    if results == True:
                        match = True
                        return(password)
                        break
            if not match:
                return
    else:
        with open(dictionary_file, errors='ignore') as dict_file:
            match = False
            dict_file_content = dict_file.read()
            passwords = re.split('\n', dict_file_content)
            for password in passwords:
                ha1 = calculate_ha1(username, realm, password)
                methods = ('INVITE', 'REGISTER', 'UPDATE', 'REFER')
                for method in methods:
                    ha2 = calculate_ha2(method, uri)
                    my_response = calculate_response(ha1, nonce, nc, cnonce, ha2)
                    results = verify_match(my_response, response)
                    if results == True:
                        match = True
                        return(password)
                        break
            if not match:
                return


def one_guess(password):
    """ manually test one password at a time
    """
    username, realm, nonce, uri, response, cnonce, \
        qop, nc = parse_packet(sip_packet)

    match = False
    methods = ('INVITE', 'REGISTER', 'UPDATE', 'REFER')
    for method in methods:
        ha1 = calculate_ha1(username, realm, password)
        ha2 = calculate_ha2(method, uri)
        my_response = calculate_response(ha1, nonce, nc, cnonce, ha2)
        results = verify_match(my_response, response)
        if results == True:
            match = True
            return(match)
            break
    if not match:
        return(match)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        sip_packet = capture_packet()
        dictionary_file = sys.argv[1]
        password = find_match(dictionary_file)
        if password:
            print("Password is {}".format(password))
        else:
            print("Password not found in {}".format(dictionary_file))
    else:
        message = "\nDescription: \tThis script will attempt to recover the password in authentication"
        message += "\nUsage: \t\t{} <dictionary-file>\n".format(sys.argv[0])
        print(message)

        # password = input("Enter password: ")
        # results = one_guess(password)
        # if results == True:
        #    print("\nCorrect match!\n")
        # if results == False:
        #    print("\nPassword does not match\n")
