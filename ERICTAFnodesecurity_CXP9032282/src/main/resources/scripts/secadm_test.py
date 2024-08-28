#!/usr/bin/python -tt
import enmscripting
import sys
import logging

 
def main():
    
    logging.basicConfig(level=logging.INFO)

    url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    command = sys.argv[4]
    to_search = sys.argv[5]

    print url + ' ' + username + ' ' + password + ' ' + command 
    logging.debug("<><><><><><><>  Client Script NodeSecurity <><><><><><><><><>")

    enm_session = enmscripting.open(url, username, password)
    cmd_result = enm_session.terminal().execute(command)
 
    #assert cmd_result.is_success_sent() is True, 'Command execute failed'
    assert cmd_result.is_command_result_available() is True, 'Command execute failed'
    assert cmd_result.http_response_code() == 200, 'Command http response should be 200'
 
    output = cmd_result.get_output()
    # Assert command output syntax
    # Assert tables / headers / rows
    # How many instances returned etc
 
    # Basic assert example / last line of the result contains to_search
    assert to_search in output[len(output)-1], \
        'Result [' + output[len(output)-1] + '] does not contain string [' + to_search + ']'
    
    logging.debug('\n'.join(cmd_result.get_output()))
 
# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()

