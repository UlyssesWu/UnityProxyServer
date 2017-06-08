#include "ProxyServer.h"
#include "Log.h"
#include "Utility.h"
#include "BitStream.h"
#include "StringCompressor.h"

#include "RakPeerInterface.h"
#include "RakNetworkFactory.h"
#include "RakSleep.h"
#include "MessageIdentifiers.h"
#include "NatPunchthroughClient.h"
#include "SocketLayer.h"

#ifdef WIN32
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <windows.h>
#include <signal.h>
#else
#include <string>
#include <iostream>
#include <signal.h>
#endif

#include <map>
#include <stdlib.h>
#include <list>
#include <queue>
#include <bitset>
#include <algorithm>

typedef std::list<RelayItem> RelayQueue;
typedef std::map<SystemAddress, SystemAddress> RelayMap;
typedef std::map<int, SystemAddress> ServerMap;
typedef std::list<int> ServerPorts;

RakPeerInterface *peer;
bool quit;
ServerPorts serverPorts;
ServerPorts usedPorts;
ServerMap serverMap;
RelayMap relayMap;
RelayQueue queue;
NatPunchthroughClient natPunchthrough;
SystemAddress facilitatorAddress = UNASSIGNED_SYSTEM_ADDRESS;

//MRB 8.27.12 -- list of peers and which port they are using, so we can disconnect them if the port owner disconnects
typedef std::list<PortUser> PortUsers;
PortUsers portUsers;

char* logfile = "proxyserver.log";
const int fileBufSize = 1024;
char pidFile[fileBufSize];

void shutdown(int sig)
{
	Log::print_log("Shutting down\n\n");
	quit = true;
}

void usage()
{
	printf("\nAccepted parameters are:\n\t"
		   "-p\tListen port (1-65535)\n\t"
		   "-d\tDaemon mode, run in the background\n\t"
		   "-l\tUse given log file\n\t"
		   "-e\tDebug level (0=OnlyErrors, 1=Warnings, 2=Informational(default), 2=FullDebug)\n\t"
		   "-c\tConnection count\n\t"
		   "-r\tRange of ports for proxied servers\n\t"
		   "-f\tFacilitator address(IP:port)\n\t"
		   "-i\tPassword for all connections\n\t"
		   "If any parameter is omitted the default value is used.\n");
}

void MsgClientInit(Packet *packet, SystemAddress targetAddress, char *password, int passwordLength, bool useNat, int clientVersion)
{

	if (!peer->IsConnected(targetAddress))
	{
		if (useNat)
		{
			Log::print_log("Doing NAT punch through to %s\n", targetAddress.ToString());
			// TODO: IMPLEMENT
			//natPunchthrough.OpenNAT(<#int destination#>, <#int facilitator#>);
			//natPunchthrough.Connect(targetAddress.ToString(false), targetAddress.port, password, passwordLength, facilitatorAddress);
		}
		else
		{
			Log::print_log("Connecting directly to server %s\n", targetAddress.ToString());
			peer->Connect(targetAddress.ToString(false), targetAddress.port, password, passwordLength, 0);
		}

		// New packet will be ID(1) + SystemAddress(6)  + ID(1) + proxy version(4) + client version(4) = 16 bytes
		RelayItem item;
		RakNet::BitStream stream;
		stream.Write((unsigned char)ID_PROXY_MESSAGE);
		stream.Write(packet->systemAddress);
		stream.Write((unsigned char)ID_REQUEST_CLIENT_INIT);
		stream.Write((int)PROXY_SERVER_PROTOCOL_VERSION);
		stream.Write((int)clientVersion);
		Log::print_log("Buffering client init, packet size is %d\n", stream.GetNumberOfBytesUsed());
		if (Log::sDebugLevel == kInformational)
		{
			for (int i=0; i<=stream.GetNumberOfBytesUsed(); i++)
			{
				printf("%x", stream.GetData()[i]);
			}
			printf("\n");
		}
		item.packet = new char[stream.GetNumberOfBytesUsed()];
		memcpy(item.packet, stream.GetData(), stream.GetNumberOfBytesUsed());
		item.length = stream.GetNumberOfBytesUsed();
		item.target = targetAddress;

		queue.push_back(item);
		Log::print_log("Target address %s, not connected. Sending connect request.\n", targetAddress.ToString());
		return;
	}
	else
	{
		RakNet::BitStream stream;
		stream.Write((unsigned char)ID_PROXY_MESSAGE);
		stream.Write(packet->systemAddress);
		stream.Write((unsigned char)ID_REQUEST_CLIENT_INIT);
		stream.Write((int)PROXY_SERVER_PROTOCOL_VERSION);
		stream.Write(clientVersion);

		peer->Send(&stream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, targetAddress, false);
		char tmpip[32];
		strcpy(tmpip, packet->systemAddress.ToString());
		Log::print_log("Proxying client init message to server at %s, sender is %s\n", targetAddress.ToString(), tmpip);
	}
}

void MsgClientRelay(RakNet::BitStream &bitStream, Packet *packet, SystemAddress targetAddress)
{
	// If target address is not connected to us (the proxy), then we need to connect first
	if (!peer->IsConnected(targetAddress))
	{
		// If not connected we need to connect and queue the message for transmission
		peer->Connect(targetAddress.ToString(false), targetAddress.port, NULL, 0, 0);

		// Current bitstream has ID(1) + SystemAddress(6) + int(4) = 11 prepended bytes
		// New will prepend a proxy relay message ID(1) + SystemAddress(6) of sender = 7 prepended bytes
		// Total message size thus decreases by 11 - 7 = 4 bytes
		RelayItem item;
		item.packet = new char[packet->length-4];
		item.packet[0] = ID_PROXY_MESSAGE;
		memcpy(item.packet+1, (void*)(&packet->systemAddress), 6);
		memcpy(item.packet+7, packet->data+11, packet->length-11);
		item.length = packet->length-4;
		item.target = targetAddress;

		queue.push_back(item);
		Log::print_log("Target address %s, not connected. Sending connect request.\n", targetAddress.ToString());
	}
	else
	{
		// Now we need to prepend proxy message ID + sender address to original message
		// packet struct).
		RakNet::BitStream stream;
		stream.Write((unsigned char)ID_PROXY_MESSAGE);
		stream.Write(packet->systemAddress);
		stream.WriteBits(bitStream.GetData()+1, bitStream.GetNumberOfBitsUsed()-8, false);

		peer->Send(&stream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, targetAddress, false);
		char tmpip[32];
		strcpy(tmpip, packet->systemAddress.ToString());
		//Log::print_log("Proxying relay message to server at %s, sender is %s\n", targetAddress.ToString(), tmpip);
	}
}

void MsgClientRelayPassthrough(RakNet::BitStream &bitStream, Packet *packet, SystemAddress targetAddress)
{
	// Now we need to prepend proxy message ID + sender address to original message
	RakNet::BitStream stream;
	stream.Write((unsigned char)ID_PROXY_MESSAGE);
	stream.Write(packet->systemAddress);
	stream.WriteBits(bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), false);

	peer->Send(&stream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, targetAddress, false);
}


char* IDtoString(const int ID)
{
	static char tmp[32];
	switch (ID)
	{
		case ID_RPC:
			strcpy(tmp, "ID_RPC");
			break;
		case ID_TIMESTAMP:
			strcpy(tmp, "ID_TIMESTAMP");
			break;
		case ID_STATE_UPDATE:
			strcpy(tmp, "ID_STATE_UPDATE");
			break;
		case ID_STATE_INITIAL:
			strcpy(tmp, "ID_STATE_INITIAL");
			break;
		case ID_CLIENT_INIT:
			strcpy(tmp,"ID_CLIENT_INIT");
			break;
		case ID_REQUEST_CLIENT_INIT:
			strcpy(tmp,"ID_REQUEST_CLIENT_INIT");
			break;
		default:
			sprintf(tmp, "Unknown ID %d", ID);
	}
	return tmp;
}

void DebugServerRelay()
{
	Log::print_log("Connection count is %d\n", peer->NumberOfConnections());
	Log::print_log("Used ports: ");
	if (Log::sDebugLevel == kInformational)
	{
		for (ServerPorts::iterator i = usedPorts.begin(); i != usedPorts.end(); i++)
			printf("%d ", *i);
		printf("\n");
	}
	Log::print_log("Server ports: ");
	if (Log::sDebugLevel == kInformational)
	{
		for (ServerPorts::iterator i = serverPorts.begin(); i != serverPorts.end(); i++)
			printf("%d ", *i);
		printf("\n");
	}
	Log::print_log("Server map: ");
	if (Log::sDebugLevel == kInformational)
	{
		for (ServerMap::iterator i = serverMap.begin(); i != serverMap.end(); i++)
			printf("[%d %s] ", i->first, i->second.ToString());
		printf("\n");
	}
}

void DebugClientRelay()
{
	Log::print_log("Connection count is %d\n", peer->NumberOfConnections());
	Log::print_log("Relay map: ");
	if (Log::sDebugLevel == kInformational)
	{
		for (RelayMap::iterator i = relayMap.begin(); i != relayMap.end(); i++)
			printf("[%s %s] ", i->first.ToString(), i->second.ToString());
		printf("\n");
	}
	Log::print_log("Relay queue: ");
	if (Log::sDebugLevel == kInformational)
	{
		for (RelayQueue::iterator i = queue.begin(); i != queue.end(); i++)
			printf("%s ", ((RelayItem)*i).target.ToString());
		printf("\n");
	}
}

// Check through relay map and disconnect all clients which were connected
// or attempting connection to this server
void CleanClient(SystemAddress serverAddress)
{
	RelayMap::iterator i = relayMap.begin();
	while (i != relayMap.end())
	{
		if (i->second == serverAddress)
		{
			Log::print_log("Disconnecting client %s\n", i->first.ToString());
			peer->CloseConnection(i->first, true);
			relayMap.erase(i++);
		}
		else
			i++;
	}
}

//MRB 8.27.12 -- disconnect any peers that were using this port, called when the port owner disconnects
void DisconnectPeersUsingPort(int port)
{
	PortUsers::iterator next = portUsers.begin();
	while (next != portUsers.end())
	{
		PortUser &item = *next;
		if (port == item.port)
		{
			Log::debug_log("Disconnecting peer %s from port %d\n", item.userAddress.ToString(), port);

			peer->CloseConnection(item.userAddress, true);

			next = portUsers.erase(next);
		}
		else
			next++;
	}

}

void CleanQueue(SystemAddress removeMe)
{
	Log::debug_log("Cleaning %s\n", removeMe.ToString());

	// If this is a server relay
	for (ServerMap::iterator i=serverMap.begin(); i!=serverMap.end(); i++)
	{
		if (i->second == removeMe)
		{
			int freePort = i->first;
			serverMap.erase(i);
			ServerPorts::iterator result = find( usedPorts.begin(), usedPorts.end(), freePort );
			if( result != usedPorts.end() )
			{
				Log::debug_log("Freeing server port %d\n", freePort);
				usedPorts.erase(result);
				// Add to the back of the list so the port is more likely not to be immediately reused
				serverPorts.push_back(freePort);

				DisconnectPeersUsingPort(freePort); //MRB 8.27.12 -- disconnect any peers that were using this port
			}
			else
			{
				Log::error_log("Failed to find server port %d in list\n", freePort);
			}
			DebugServerRelay();
			return;
		}
	}

	// Process client relay disconnection

	if (!queue.empty())
	{
		RelayQueue::iterator next = queue.begin();
		for (RelayQueue::iterator i = next; i != queue.end(); i=next)
		{
			RelayItem &item = *i;
			next++;
			if (removeMe == item.target)
			{
				Log::debug_log("Removing queued message to target at %s\n", removeMe.ToString());
				queue.erase(i);
			}
		}
	}
	// Notify server that the client has disconnected
	RakNet::BitStream stream;
	stream.Write((unsigned char)ID_PROXY_MESSAGE);
	stream.Write(removeMe);
	stream.Write((unsigned char)ID_DISCONNECTION_NOTIFICATION);
	if (!peer->Send(&stream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, relayMap[removeMe], false))
	{
		Log::error_log("Failed to send clean disconnect notification for client %s\n", removeMe.ToString());
	}

	// If this is on the receiving end of a client address, then this is a server
	bool isServer = false;
	std::queue<SystemAddress> remove;
	RelayMap::iterator i;
	for (i=relayMap.begin(); i!=relayMap.end(); i++)
	{
		if (i->second == removeMe)
		{
			isServer = true;
			remove.push(i->first);
		}
	}
	// If this is a server scroll through all addresses in the relay map and disconnect the clients.
	if (isServer)
	{
		Log::debug_log("%s is a server\n", removeMe.ToString());
		while (!remove.empty())
		{
			Log::print_log("Disconnecting client %s\n", remove.front().ToString());
			relayMap.erase(remove.front());
			peer->CloseConnection(remove.front(), true);
			remove.pop();
		}
	}

	// If the server is in the relay map and there is a connection to him and there is
	// no one else in the relay map using that server, then its ok to remove and disconnect
	if (relayMap.count(removeMe))
	{
		Log::debug_log("Count is %d\n", relayMap.count(removeMe));
		// Grab the address of the server
		i = relayMap.find(removeMe);
		SystemAddress targetServer = i->second;
		// Remove instance of server accociated with disconnected client
		relayMap.erase(removeMe);
		// Check if anyone else is using the same server
		bool inUse = false;
		for (i=relayMap.begin(); i!=relayMap.end(); i++)
		{
			if (i->second == targetServer)
				inUse = true;
		}
		// No one else is using the clients server, then its ok to diconnect
		if (!inUse)
		{
			Log::print_log("Diconnecting from unused server %s\n", targetServer.ToString());
			peer->CloseConnection(targetServer, true);
		}
	}
	DebugClientRelay();
}

int main(int argc, char *argv[])
{
	quit = false;
	int connectionCount = 1000;
	int listenPort = 10746;
	int startPort = 50110;
	int endPort = 50120;
	int defaultFacilitatorPort = 50005;
	int portCount = endPort - startPort + 1;
	bool useLogFile = false;
	bool daemonMode = false;

	// Default debug level is informational, so you see an overview of whats going on.
	Log::sDebugLevel = kInformational;

#ifndef WIN32
	setlinebuf(stdout);
#endif
	std::map<SystemAddress, SystemAddress> addresses;
	peer = RakNetworkFactory::GetRakPeerInterface();

	for (int i = 1; i < argc; i++)
	{
		if (strlen(argv[i]) == 2 && argc>=i+1)
		{
			switch (argv[i][1])
			{
				case 'd':
				{
					daemonMode = true;
					break;
				}
				case 'p':
					listenPort = atoi(argv[i+1]);
					i++;
					if (listenPort < 1 || listenPort > 65535)
					{
						fprintf(stderr, "Listen port is invalid, should be between 0 and 65535.\nIt is also advisable to use a number above well known ports (>1024).\n");
						return 1;
					}
					break;
				case 'c':
				{
					connectionCount = atoi(argv[i+1]);
					i++;
					if (connectionCount < 0)
					{
						fprintf(stderr, "Connection count must be higher than 0.\n");
						return 1;
					}
					break;
				}
				case 'l':
				{
					useLogFile = Log::EnableFileLogging(logfile);
					break;
				}
				case 'e':
				{
					int debugLevel = atoi(argv[i+1]);
					Log::sDebugLevel = debugLevel;
					i++;
					if (debugLevel < 0 || debugLevel > 9)
					{
						fprintf(stderr, "Log level can be 0(errors), 1(warnings), 2(informational), 9(debug)\n");
						return 1;
					}
					break;
				}
				case 'i':
				{
					peer->SetIncomingPassword(argv[i+1], strlen(argv[i+1]));
					i++; //ULY 170608: Fix silly parsing issue.
					break;
				}
				case 'r':
				{
					std::string range(argv[i+1]);
					std::string::size_type seperator = range.find(":");
					if (seperator!= std::string::npos) {
						startPort = atoi(range.substr(0,seperator).c_str());
						endPort = atoi(range.substr(seperator+1,range.length()).c_str());
						portCount = endPort - startPort + 1;	//MRB 9.18.12: Update number of ports being used!
					}
					i++;
					break;
				}
				case 'f':
				{
					std::string facilitatorString(argv[i+1]);
					std::string::size_type seperator = facilitatorString.find(":");
					if (seperator!= std::string::npos) {
						facilitatorAddress.SetBinaryAddress(facilitatorString.substr(0,seperator).c_str());
						facilitatorAddress.port = atoi(facilitatorString.substr(seperator+1,facilitatorString.length()).c_str());
					}
					i++;
					break;
				}
				case '?':
					usage();
					return 0;
				default:
					printf("Parsing error, unknown parameter %s\n\n", argv[i]);
					usage();
					return 1;
			}
		}
		else
		{
			printf("Parsing error, incorrect parameters\n\n");
			usage();
			return 1;
		}
	}

#ifndef WIN32
	if (daemonMode)
	{
		printf("Running in daemon mode, file logging enabled...\n");
		if (!useLogFile)
			useLogFile = Log::EnableFileLogging(logfile);
		// Don't change cwd to /
		// Beware that log/pid files are placed wherever this was launched from
		daemon(1, 0);
	}

	if (!WriteProcessID(argv[0], &pidFile[0], fileBufSize))
		perror("Warning, failed to write own PID value to PID file\n");
#endif

	if (facilitatorAddress == UNASSIGNED_SYSTEM_ADDRESS)
	{
		char* address;
		address = const_cast<char*>(SocketLayer::Instance()->DomainNameToIP("facilitator.unity3d.com"));
		if (address)
		{
			facilitatorAddress.SetBinaryAddress(address);
		}
		else
		{
			Log::error_log("Cannot resolve facilitator address");
			return 1;
		}
		facilitatorAddress.port = defaultFacilitatorPort;
	}

	Log::startup_log("Proxy Server version %s\n", PROXY_SERVER_VERSION);
	Log::startup_log("Listen port set to %d\n", listenPort);
	Log::startup_log("Server relay ports set to %d to %d (%d ports)\n", startPort, endPort, portCount);
	Log::startup_log("Using facilitator at %s\n", facilitatorAddress.ToString());
	SocketDescriptor *sds = new SocketDescriptor[portCount+1];	//MRB 9.18.12: +1 to allow for listenPort socket
	sds[0] = SocketDescriptor(listenPort, 0);
	int port = startPort;
	for (int i=1; i<=portCount; i++)			   	//MRB 9.18.12: 'less than equal' instead of 'less than' so endPort is actually used
	{
		sds[i] = SocketDescriptor(port, 0);
		serverPorts.push_back(port++);
	}
	bool r = peer->Startup(connectionCount, 10, sds, portCount+1);	  	//MRB 9.18.12: +1 to allow for listenPort socket

	if (!r)
	{
		Log::error_log("Some of the relay ports are in use. Please specify some other ports by -r xxxx:xxxx"); //ULY 170608: Report port in use.
	}

	delete[] sds;	//MRB 9.18.12: Use array delete... undefined behavior otherwise

	peer->SetMaximumIncomingConnections(connectionCount);

	// Register signal handler
	if (signal(SIGINT, shutdown) == SIG_ERR || signal(SIGTERM, shutdown) == SIG_ERR)
		Log::error_log("Problem setting up signal handler");
	else
		Log::startup_log("To exit the proxy server press Ctrl-C\n----------------------------------------------------\n");

	// Set up connection to facilitator
	Log::print_log("Connecting to %s\n", facilitatorAddress.ToString());
	if (!peer->Connect(facilitatorAddress.ToString(false), facilitatorAddress.port,0,0))
	{
		Log::error_log("Failed to connect to NAT facilitator at %s\n", facilitatorAddress.ToString());
	}
	else
	{
		Log::print_log("Sent connect request to facilitator at %s\n", facilitatorAddress.ToString());
	}
	peer->AttachPlugin(&natPunchthrough);

	Packet *packet;
	while (!quit)
	{
ReceiveAnotherPacket:						//MRB 8.21.12 -- added goto label (see below 'MRB' comments for explanation)
		packet=peer->ReceiveIgnoreRPC();
		while (packet)
		{
			Log::debug_log("Received packet on port %u\n", packet->rcvPort);
			if (packet->rcvPort != listenPort)
			{
				// Client trying to connect to an invalid address
				if (packet->rcvPort == 0 && packet->data[0] == ID_CONNECTION_ATTEMPT_FAILED)
				{
					CleanClient(packet->systemAddress);
					break;
				}
				// DEBUG: Sanity check
				ServerPorts::iterator result = find( usedPorts.begin(), usedPorts.end(), packet->rcvPort );
				if( result == usedPorts.end())
				{
					Log::error_log("Communication received on uninitialized server port %d\n", packet->rcvPort);
					int IDlocation = 0;
					if (packet->data[0] == ID_TIMESTAMP)
						IDlocation = 5;
					Log::error_log("Rejected message from client at %s, ID of message is %s\n", packet->systemAddress.ToString(), IDtoString(packet->data[IDlocation]));
					break;
				}


				//MRB 8.27.12 -- keep track of who is using this port, add to our port user list on any new connections and remove from list on disconnects
				PortUser portUser;
				portUser.userAddress = packet->systemAddress;
				portUser.port = packet->rcvPort;

				if (packet->data[0] == ID_NEW_INCOMING_CONNECTION)
				{
					portUsers.push_back(portUser);
					break;
				}

				if (packet->data[0] == ID_DISCONNECTION_NOTIFICATION || packet->data[0] == ID_CONNECTION_LOST)
				{
					// DEBUG
					Log::print_log("%s has diconnected\n", packet->systemAddress.ToString());
					DebugServerRelay();

					//MRB 8.27.12 -- peer is no longer using this port
					portUsers.remove(portUser);
				}

				SystemAddress targetAddress;
				RakNet::BitStream bitStream(packet->data, packet->length, false);
				bitStream.IgnoreBits(8); // Ignore the ID_...

				// Lookup target address from map
				if (serverMap.count(packet->rcvPort) != 0)
					targetAddress = serverMap[packet->rcvPort];
				else
					Log::error_log("Error: Relay failed for client at %s, server address not found\n", packet->systemAddress.ToString());

				char tmp[32];
				strcpy(tmp, packet->systemAddress.ToString());
				int IDlocation = 0;
				if (packet->data[0] == ID_TIMESTAMP)
					IDlocation = 5;
				Log::debug_log("Relaying for client at %s, to server at %s, ID of relayed message is %s\n", tmp, targetAddress.ToString(), IDtoString(packet->data[IDlocation]));

				MsgClientRelayPassthrough(bitStream, packet, targetAddress);
				break;
			}
			switch (packet->data[0])
			{
				case ID_DISCONNECTION_NOTIFICATION:
					Log::print_log("%s has diconnected\n", packet->systemAddress.ToString());
					CleanQueue(packet->systemAddress);
					CleanClient(packet->systemAddress);
					break;
				case ID_CONNECTION_LOST:
					Log::print_log("Connection to %s lost\n", packet->systemAddress.ToString());
					CleanQueue(packet->systemAddress);
					CleanClient(packet->systemAddress);
					break;
				case ID_NEW_INCOMING_CONNECTION:
					Log::print_log("New connection established to %s\n", packet->systemAddress.ToString());
					break;
				case ID_CONNECTION_REQUEST_ACCEPTED:
					Log::print_log("Connected to %s\n", packet->systemAddress.ToString());
					if (!queue.empty())
					{
						int totalSize = queue.size();
						Log::debug_log("Relay queue has %d elements\n", queue.size());

						// Check whole queue and send everything with this server as target
						RelayQueue::iterator next = queue.begin();
						while (next != queue.end())
						{
							RelayItem &item = *next;
							if (packet->systemAddress == item.target)
							{
								RakNet::BitStream bitStream;
								bitStream.Write(item.packet, item.length);
								//for (int i=0; i<=item.length; i++)
								//	printf("%x", item.packet[i]);
								//printf("\n");
								peer->Send(&bitStream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, item.target, false);

								Log::debug_log("Sending queued message to target at %s\n", item.target.ToString());

								//delete[] item->packet;
								next = queue.erase(next);
							}
							else
								next++;
						}

						Log::debug_log("%d elements sent from queue to target\n", totalSize - queue.size());
					}
					break;
				case ID_CONNECTION_ATTEMPT_FAILED:
				{
					Log::error_log("Failed to connect to %s\n", packet->systemAddress.ToString());
					CleanQueue(packet->systemAddress);
					CleanClient(packet->systemAddress);
					break;
				}
				case ID_ALREADY_CONNECTED:
				{
					break;
				}
				case ID_NAT_TARGET_NOT_CONNECTED:
				{
					SystemAddress systemAddress;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(systemAddress);
					Log::error_log("NAT target %s is not connected to the facilitator\n", systemAddress.ToString());
					CleanClient(systemAddress);
					break;
				}
				case ID_NAT_CONNECTION_TO_TARGET_LOST:
				{
					SystemAddress systemAddress;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(systemAddress);
					Log::error_log("NAT connection to %s lost\n", systemAddress.ToString());
					CleanClient(systemAddress);
					break;
				}
			case ID_PROXY_INIT_MESSAGE:
				{
					SystemAddress targetAddress;
					int proxyVersion;	// Proxy protocol version of the connecting client
					int clientVersion;	// Network protocol version of the connecting client
					char *password;
					int passwordLength = 0;
					bool useNat;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(proxyVersion);
					// Check target address of relayed message, memorize it for future use
					bitStream.Read(targetAddress);
					if (bitStream.ReadBit())
					{
						bitStream.Read(passwordLength);
						password = new char[passwordLength];
						bitStream.Read(password, passwordLength);
					}
					bitStream.Read(useNat);
					bitStream.Read(clientVersion);
					relayMap[packet->systemAddress] = targetAddress;

					char tmp[32];
					strcpy(tmp, targetAddress.ToString());
					Log::print_log("Received relay init message from %s, target is %s, proxy protocol version %d, network protocol version %d\n", packet->systemAddress.ToString(), tmp, proxyVersion, clientVersion);

					MsgClientInit(packet, targetAddress, password, passwordLength, useNat, clientVersion);
					if (passwordLength > 0)
						delete[] password;
				}
				break;
			case ID_PROXY_SERVER_INIT:
				{
					//SystemAddress targetAddress;
					int proxyVersion;

					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...
					bitStream.Read(proxyVersion);

					Log::print_log("Received server init message from %s, proxy protocol version %d\n", packet->systemAddress.ToString(), proxyVersion);

					unsigned short freePort = 0;
					RakNet::BitStream responseStream;
					if (serverPorts.size() > 0)
					{
						freePort = serverPorts.front();
						serverPorts.pop_front();
						usedPorts.push_front(freePort);
						responseStream.Write((unsigned char)ID_PROXY_SERVER_INIT);
						responseStream.Write((int)PROXY_SERVER_PROTOCOL_VERSION);
						responseStream.Write(freePort);
						peer->Send(&responseStream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, packet->systemAddress, false);
						serverMap[freePort] = packet->systemAddress;
						Log::print_log("Server %s assigned port %d\n", packet->systemAddress.ToString(), freePort);
					}
					else
					{
						responseStream.Write((unsigned char)ID_PROXY_SERVER_INIT);
						responseStream.Write((int)PROXY_SERVER_PROTOCOL_VERSION);
						responseStream.Write((unsigned short)0);
						peer->Send(&responseStream, HIGH_PRIORITY, RELIABLE_ORDERED, 0, packet->systemAddress, false);
						Log::error_log("Server %s rejected as no server port is free\n", packet->systemAddress.ToString());
					}
					//relayMap[packet->systemAddress] = targetAddress;
				}
				break;
			// Relay message from clients
			case ID_PROXY_CLIENT_MESSAGE:
				{
					SystemAddress targetAddress;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...

					// Lookup target address from map
					if (relayMap.count(packet->systemAddress) != 0)
						targetAddress = relayMap[packet->systemAddress];
					else
						Log::error_log("Error: Relay failed for client at %s, target address not found\n", packet->systemAddress.ToString());

					char tmp[32];
					strcpy(tmp, packet->systemAddress.ToString());
					int IDlocation = 1;
					if (packet->data[1] == ID_TIMESTAMP)
						IDlocation = 6;
					Log::debug_log("Relaying for client at %s, to server at %s, ID of relayed message is %s\n", tmp, targetAddress.ToString(), IDtoString(packet->data[IDlocation]));

					MsgClientRelay(bitStream, packet, targetAddress);
				}
				break;
			// Relay message from servers
			case ID_PROXY_SERVER_MESSAGE:
				{
					SystemAddress clientAddress;
					RakNet::BitStream bitStream(packet->data, packet->length, false);
					bitStream.IgnoreBits(8); // Ignore the ID_...

					// To what client should this message be relayed to
					bitStream.Read(clientAddress);

					peer->Send(reinterpret_cast<const char*>(packet->data+7), packet->length-7, HIGH_PRIORITY, RELIABLE_ORDERED, 0, clientAddress, false);

					char tmp[32];
					strcpy(tmp, packet->systemAddress.ToString());
					int IDlocation = 7;
					if (packet->data[7] == ID_TIMESTAMP)
						IDlocation = 12;
					Log::debug_log("Relaying for server at %s, to client at %s, ID of relayed message is %s\n", tmp, clientAddress.ToString(), IDtoString(packet->data[IDlocation]));
				}
				break;
			case ID_INVALID_PASSWORD:
				{
					SystemAddress clientAddress = UNASSIGNED_SYSTEM_ADDRESS;
					// A server rejected connection, need to find appropriate client address and notify him
					for (RelayMap::iterator i = relayMap.begin(); i != relayMap.end(); i++) {
						if ((*i).second == packet->systemAddress) {
							clientAddress = (*i).first;
							break;
						}
					}
					if (clientAddress != UNASSIGNED_SYSTEM_ADDRESS) {
						peer->Send(reinterpret_cast<const char*>(packet->data), packet->length, HIGH_PRIORITY, RELIABLE_ORDERED, 0, clientAddress, false);
						char tmp[32];
						strcpy(tmp, packet->systemAddress.ToString());
						Log::error_log("Send invalid password from %s notification to client at %s\n", tmp, clientAddress.ToString());
					}
					else
					{
						Log::error_log("Failed to relay invalid password notification to any client for server at %s\n", packet->systemAddress.ToString());
					}
				}
				break;
			// Relay message from proxies
				default:
					Log::error_log("Unknown ID %d from %s\n", packet->data[0], packet->systemAddress.ToString());
			}
			peer->DeallocatePacket(packet);
			//packet=peer->Receive();			//MRB 8.21.12 -- Wrong Receive function to call. This function processes RPC packets internally and doesn't return them to caller, so we never get a chance to relay them.
			packet=peer->ReceiveIgnoreRPC();	//MRB 8.21.12 -- This is the correct function to call, as was done above at the top of this while loop.
		} //end while, loops back to process next packet

		//MRB 8.21.12 -- New section to deal with case where packet was received on non-listen port, which exits the loop after processing the packet
		if (packet)
		{
			peer->DeallocatePacket(packet);  //Packets received on non-listen ports were never Deallocated!
			goto ReceiveAnotherPacket;		 //We need to check for more packets before going to sleep. Otherwise, if we have continuous incoming traffic, packets get buffered and we slowly build in more and more latency.
		}
		//MRB 8.21.12 -- section end

		RakSleep(30);
	}

	if (pidFile)
	{
		if (remove(pidFile) != 0)
			fprintf(stderr, "Failed to remove PID file at %s\n", pidFile);
	}
	peer->Shutdown(100,0);
	RakNetworkFactory::DestroyRakPeerInterface(peer);

	return 0;
}

