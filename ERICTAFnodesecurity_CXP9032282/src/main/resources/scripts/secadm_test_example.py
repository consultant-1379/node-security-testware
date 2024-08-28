import enmscripting
import sys

def main():
	enm_session = enmscripting.open("https://enmapache.athtem.eei.ericsson.se","administrator","TestPassw0rd")
	with open("EndEntity_1.xml", 'r') as file_to_import:
		command = "pkiadm etm -c -xf file:EndEntity_1.xml"
		response = enm_session.terminal().execute(command, file=file_to_import)
		output = response.get_output()
		print output

# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
