import enmscripting
import sys
import re
def lookFor(l, s):
	#print "mari  " + s
	#print "maledetta  " + l
	m = re.search(s, l)
	if m:
		found = m.group(1)
		return found
	else:
		return ''
def checkAlreadyPresent(name,rows):
	for line in rows:
		if lookFor(line,"[0-9]+[\t ]+(" + name + ")[\t ]+")!= "":
			return True
	return False

def createCPIfNotExists(enm_session):
	certificate_profile = "SLS_USER_CP" 
	response_cp = enm_session.terminal().execute("pkiadm pfm -l -type certificate")	
	if not checkAlreadyPresent(certificate_profile,response_cp.get_output()):
		print "NOT FOUND CERTIFICATE PROFILE  WITH NAME  " + certificate_profile 
		with open("Entity_Certificate_Profile.xml", 'r') as file_to_import:
			command = "pkiadm pfm -c -xf file:Entity_Certificate_Profile.xml"
			response = enm_session.terminal().execute(command, file=file_to_import)
			output = response.get_output()
			print output

def createEPIfNotExists(enm_session):
	entity_profile = "SLS_USER_EP" 
	response_ep = enm_session.terminal().execute("pkiadm pfm -l -type entity")	
	if not checkAlreadyPresent(entity_profile,response_ep.get_output()):
		print "NOT FOUND ENTITY PROFILE  WITH NAME  " + entity_profile 
		with open("Entity_Entity_Profile.xml", 'r') as file_to_import:
			command = "pkiadm pfm -c -xf file:Entity_Entity_Profile.xml"
			response = enm_session.terminal().execute(command, file=file_to_import)
			output = response.get_output()
			print output


def createEEIfNotExists(enm_session,entity_name):
	response = enm_session.terminal().execute("pkiadm etm -l -type ee")
	if not checkAlreadyPresent(entity_name,response.get_output()):
		print "NOT FOUND ENTITY WITH NAME  " + entity_name
		with open("Entity.xml", 'r') as file_to_import:
			command = "pkiadm etm -c -xf file:Entity.xml"
			response = enm_session.terminal().execute(command, file=file_to_import)
			output = response.get_output()
			print output
	else:
		print "ENTITY WITH NAME  " + entity_name + " ALREADY PRESENT"


	
def main():
	entity_name = sys.argv[1]
	enm_session = enmscripting.open("https://enmapache.athtem.eei.ericsson.se","administrator","TestPassw0rd")
	createCPIfNotExists(enm_session)
	createEPIfNotExists(enm_session)
	createEEIfNotExists(enm_session,entity_name)
		


# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
