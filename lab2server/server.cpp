/* 
 * File:   server.cpp
 * Author: anileeli
 *
 * Created on November 12, 2018, 8:45 PM
 */

#include <cstdlib>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <unordered_map>
#include <unordered_set>

#define SESSION_NOT_FOUND "No session found!"
#define ACK_DATA "NoData"

#define BACKLOG 10       // How many pending connections queue will hold
#define MAXDATASIZE 1380 // Max number of bytes we can get at once 

using namespace std;

// Defines control packet types
enum msgType {
    LOGIN,
    LO_ACK,
    LO_NAK,
    EXIT,
    JOIN,
    JN_ACK,
    JN_NAK,
    LEAVE_SESS,
    LS_ACK,
    LS_NAK,
    NEW_SESS,
    NS_ACK,
    NS_NAK,
    MESSAGE,
    QUERY,
    QU_ACK,
    DIRMESSAGE,
    DMESS_ACK,
    DMESS_NAK
};


// Message structure to be serialized when sending messages
struct message {
    unsigned int type;
    unsigned int size;
    string source;
    string data;
};

// Keeps a list of all users that are permitted to login
unordered_map<string, string> permittedClientList({
    {"sadman", "ahmed"},
    {"eliano", "anile"},
    {"chris", "pua"},
    {"username", "password"},
    {"hamid", "timorabadi"},
    {"john", "smith"}
}); 

// Key is file descriptor, value is client username and password
unordered_map<int, pair<string, string>> clientList;

// Key is session name, value is set of file descriptors describing clients
// connected to the session
unordered_map<string, unordered_set<int>> sessionList;

// Key is session name, value is set to the be the password set by the client
// making the session
unordered_map<string, string> sessionPasswordList;

// Get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}


// Creates socket that listens for new connections and returns the file descriptor
int createListenerSocket(const char* portNum)
{
    int listener;     // listening socket descriptor
    int yes=1;        // for setsockopt() SO_REUSEADDR, below
    int rv;
    
    struct addrinfo hints, *ai, *p;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    if ((rv = getaddrinfo(NULL, portNum, &hints, &ai)) != 0)
    {
        fprintf(stderr, "server: %s\n", gai_strerror(rv));
        exit(1);
    }
    
    for(p = ai; p != NULL; p = p->ai_next)
    {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) continue;
        
        // lose the pesky "address already in use" error message
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0)
        {
            close(listener);
            continue;
        }

        break;
    }

    // if we got here, it means we didn't get bound
    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(2);
    }

    freeaddrinfo(ai); // all done with this

    // listen
    if (listen(listener, BACKLOG) == -1) {
        perror("listen");
        exit(3);
    }
    
    return listener;
}


// Create a packet string from a message structure
string stringifyMessage(const struct message* data)
{   
    string dataStr = to_string(data->type) + " " + to_string(data->size) 
                     + " " + data->source + " " + data->data;
    return dataStr;
}


// Creates a message structure from a packet (string)
struct message messageFromPacket(const char* buf)
{
    string buffer(buf);
    stringstream ss(buffer);
    struct message packet;
    ss >> packet.type >> packet.size >> packet.source;
    if(!getline(ss, packet.data)) packet.data = ACK_DATA;
    return packet;
}


// Return the sessionID that the sockfd is connected to
// Returns "NoSessionFound" if session could not be found
string clientSockfdToSessionID (int sockfd)
{
    for (auto session = sessionList.begin(); session != sessionList.end(); session++)
    {
        // Check if the given client is connected to this session
        auto client = session->second.find(sockfd);
        if(client != session->second.end()) return session->first;
    }

    // Session could not be found 
    return SESSION_NOT_FOUND;
}


// Sends a message to client in the following format:
//   message = "<type> <data_size> <source> <data>"
// Returns true if message is successfully sent
bool sendToClient(struct message *data, int sockfd)
{
    int numBytes;
    string dataStr = stringifyMessage(data);

    if(dataStr.length() + 1 > MAXDATASIZE) return false;
    if((numBytes = send(sockfd, dataStr.c_str(), dataStr.length() + 1, 0)) == -1)
    {
        perror("send");
        return false;
    }
    return true;
}


// Send an acknowledge to a client if their login is successful
void acknowledgeLogin(int sockfd)
{
    struct message loginAck;
    loginAck.type = LO_ACK;
    loginAck.size = 0;
    loginAck.source = "SERVER";
    loginAck.data = "";
    
    sendToClient(&loginAck, sockfd);
}

// Checks if the user can login to the server
// If not, string returned is reason for error
pair<bool, string> canUserConnect(string userID, string password)
{
    // Checks if the user is on the list of permitted clients
    if(permittedClientList.find(userID) != permittedClientList.end())
    {
        // Checks if the user is already logged in 
        for (auto client = clientList.begin(); client != clientList.end(); client++)
        {
            if(client->second.first == userID)
            {
                return make_pair(false, "User is already logged in!");
            }
        }
        
        // Check if password is correct
        if(password != permittedClientList.find(userID)->second)
        {
            return make_pair(false, "Password is incorrect!");
        }
        return make_pair(true, ACK_DATA); 
    }
    return make_pair(false, "Username does not exist!");
}


// Logs a client described by a file descriptor into the server
// Returns true if successful
// TODO Check if the client is double logging in
bool loginClient(int sockfd)
{
    char buffer[MAXDATASIZE];
    int numBytes;
    struct message loginInfo;
    struct message ack;
    ack.size = 0;
    ack.source = "SERVER";
    ack.data = ACK_DATA;
    
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return false;
    }
    else
    {
        string s(buffer);
        stringstream ss(s);
        ss >> loginInfo.type >> loginInfo.size
           >> loginInfo.source >> loginInfo.data;
    }
    
    // Check if user is permitted to connect to the server
    pair<bool, string> userConnectReq = canUserConnect(loginInfo.source, loginInfo.data);
    if (userConnectReq.first == false)
    {
        // Send back reason for error
        ack.type = LO_NAK;
        ack.data = userConnectReq.second;
        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return false;
    }
    
    else
    {
        // Client can login, add it to the list of active clients
        clientList.insert(make_pair(sockfd, make_pair(loginInfo.source, loginInfo.data)));
        
        // No data sent back
        ack.type = LO_ACK;
        
        sendToClient(&ack, sockfd);
        return true;
    }
}

// Checks if the password corresponds with the session being attempted to join
bool checkSessionPassword (string sessionID, string sessionPassword)
{
    auto currentSession = sessionPasswordList.find(sessionID);

    if (currentSession -> second == sessionPassword) return true;
    else return false; 

}

// Adds client to the specified session
// If the session exists and they aren't already in a session, it sends back the
// session they were added to
// Otherwise, it sends back the reason they couldn't be added to the specified session
// Returns true if successful
bool joinSession (int sockfd, string sessionData)
{
    struct message ack;
    ack.source = "SERVER";

    string sessionID, sessionPassword;  
    stringstream ss(sessionData);
    ss >> sessionID >> sessionPassword;
    
    // Find list of clients connected to the given session name
    auto session = sessionList.find(sessionID);
    
    // Find session the client is connected to (if any)
    string currentSessionID = clientSockfdToSessionID(sockfd);
    
    // Checking that session exists and client is not already in a session
    if (sessionID != ACK_DATA &&
        currentSessionID == SESSION_NOT_FOUND &&
        session != sessionList.end() && 
        checkSessionPassword(sessionID, sessionPassword))
    {        
        
        // Add client to the session
        session->second.insert(sockfd);

        // Send response with the data as the sessionID
        ack.type = JN_ACK;
        ack.data = sessionID;
        ack.size = ack.data.length() + 1;

        sendToClient(&ack, sockfd);
        return true;
        
    }
    
    // Session does not exist or client is already in a session
    else 
    {
        ack.type = JN_NAK;
        
        if (sessionID == ACK_DATA) ack.data = "No session ID was provided!";
        else if(currentSessionID != SESSION_NOT_FOUND) ack.data = "Already in a session!";
        else if (session == sessionList.end()) ack.data = "Session not found!";
        else if (checkSessionPassword(sessionID, sessionPassword) == false) ack.data = "Password is incorrect!";


        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return false;
    }
}


// Removes client from their current session.
// If they're in a session, it sends back the session they were removed from
// Otherwise, it sends back the reason they couldn't leave the specified session
// Returns true if successful
bool leaveSession (int sockfd)
{
    struct message ack;
    ack.source = "SERVER";
\
    string currentSessionID = clientSockfdToSessionID(sockfd);
    
    // Check if client is in a session
    if (currentSessionID != SESSION_NOT_FOUND)
    {
        // Remove client from session
        auto currentSession = sessionList.find(currentSessionID);
        currentSession->second.erase(sockfd);
        
        // No more clients in the session
        if(currentSession->second.empty()) 
        {
            sessionList.erase(currentSessionID);
            sessionPasswordList.erase(currentSessionID);
        }
        
        ack.type = LS_ACK;
        ack.data = currentSessionID;
        ack.size = ack.data.length() + 1;

        sendToClient(&ack, sockfd);
        return true;
    }
    else
    {
        ack.type = LS_NAK;
        ack.data = "Not in a session!";
        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return false;
    }
}


// Create a new session in the session list and add the requesting client to it
// If the session doesn't exist, it creates it and adds the client to it, and
// sends back the sessionID
// Otherwise, it sends back the reason why it couldn't be created
// Returns true if successful
bool createSession(int sockfd, string sessionData)
{   
    struct message ack;
    ack.source = "SERVER";
    
    if(clientSockfdToSessionID(sockfd) != SESSION_NOT_FOUND)
    {
        ack.type = NS_NAK;
        ack.data = "Already in a session!";
        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return false;
    }
    
    string sessionID, sessionPassword;
    stringstream ss(sessionData);
    
    ss >> sessionID >> sessionPassword;
    
    // Insert returns a pair describing if the insertion was successful
    auto res = sessionList.insert(make_pair(sessionID, unordered_set<int>({sockfd})));
    if(res.second == false)
    {
        ack.type = NS_NAK;
        ack.data = "Session already exists!";
        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return false;
    }
    else if (sessionID == ACK_DATA)
    {
        ack.type = NS_NAK;
        ack.data = "No session ID was provided!";
        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return false;  
    }
    
    else
    {
        // Recording password of the created session list
        sessionPasswordList.insert(make_pair(sessionID, sessionPassword));
        
        ack.type = NS_ACK;
        ack.data = sessionID;
        ack.size = ack.data.length() + 1;
        
        sendToClient(&ack, sockfd);
        return true;
    }
}


// Send an acknowledge to a client for requesting a list
void acknowledgeList(int sockfd, string buffer)
{
    struct message listAck;
    listAck.type = QU_ACK;
    listAck.size = buffer.length() + 1;
    listAck.source = "SERVER";
    listAck.data = buffer;
    
    sendToClient(&listAck, sockfd);
}


void createList(int sockfd)
{
    string buffer = "\nClients Online: ";
    
    for(auto it : clientList){
        buffer += it.second.first + " ";
    }
    
    
    buffer += "\nAvailable Sessions: ";
    for(auto it : sessionList){
        buffer += it.first + " ";
    }
    
    acknowledgeList(sockfd, buffer);
}


// Sends a direct message to a client specified in the data of the given packet
// If the client doesn't exist, inform sender
// Returns true if message sent successfully
bool sendDirectMessage(struct message packet, int senderfd)
{
    struct message dirMessAck;
    dirMessAck.source = "SERVER";
    
    stringstream ss(packet.data);
    string receiverID, message;
    ss >> receiverID;
    
    for(auto const & client : clientList)
    {
        if(client.second.first == receiverID)
        {
            // Don't send to yourself
            if(client.first == senderfd)
            {
                dirMessAck.type = DMESS_NAK;
                dirMessAck.data = "Can't send message to yourself!";
                dirMessAck.size = dirMessAck.data.length() + 1;
                sendToClient(&dirMessAck, senderfd);
                
                return false;
            }
            
            // Send message to receiver
            getline(ss, message);
            message.erase(0, 1); // Remove extra space
            packet.data = message;
            sendToClient(&packet, client.first);
            
            // Tell sender the message was delivered
            dirMessAck.type = DMESS_ACK;
            dirMessAck.data = receiverID;
            dirMessAck.size = dirMessAck.data.length() + 1;
            sendToClient(&dirMessAck, senderfd);
            
            return true;
        }
    }
    
    // Inform sender the user does not exist
    dirMessAck.type = DMESS_NAK;
    dirMessAck.data = "User '" + receiverID + "' does not exist!";
    dirMessAck.size = dirMessAck.data.length() + 1;
    sendToClient(&dirMessAck, senderfd);
    
    return false;
}

int main(int argc, char** argv)
{
    fd_set master;    // Master file descriptor list
    fd_set read_fds;  // Temp file descriptor list for select()
    int fdmax;        // Maximum file descriptor number

    char remoteIP[INET6_ADDRSTRLEN];

    if(atoi(argv[1]) > 65535)
    {
        cout << "Choose a valid port!" << endl;
        return 0;
    }
    int listener = createListenerSocket(argv[1]);
    
    cout << "Waiting for connections..." << endl;
    
    // Clear master and temp sets and add the listener socket to master
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(listener, &master);

    // Keep track of the biggest file descriptor
    fdmax = listener;

    // Main loop
    while(1)
    {        
        read_fds = master; // copy master list
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1)
        {
            perror("select");
            exit(4);
        }

        // Run through the existing connections looking for data to read
        for(int i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds)) // Part of the tracked file descriptors
            { 
                if (i == listener) // Handle new connections
                {
                    struct sockaddr_storage remoteaddr; // client address
                    socklen_t addrlen = sizeof(remoteaddr);
                    int newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);

                    if (newfd == -1) perror("accept");
                    else
                    {   
                        if(loginClient(newfd) == true)
                        {
                            FD_SET(newfd, &master); // add to master set
                            if (newfd > fdmax) fdmax = newfd;

                            printf("server: new connection from %s on socket %d\n",
                                inet_ntop(remoteaddr.ss_family,
                                    get_in_addr((struct sockaddr*)&remoteaddr),
                                    remoteIP, INET6_ADDRSTRLEN),
                                    newfd);
                        }
                        else
                        {
                            cout << "Attempted connection failed" << endl;
                            close(newfd);
                        }
                    }             
                }
                
                else // Handle other commands from client
                {
                    int nbytes;
                    char buf[MAXDATASIZE];

                    if ((nbytes = recv(i, buf, MAXDATASIZE, 0)) <= 0)
                    {
                        // Got error or connection closed by client
                        if (nbytes == 0) // Connection closed
                        {
                            printf("server: socket %d hung up\n", i);
                            clientList.erase(i); // Remove client
                            
                            // Remove client from a session
                            string sessionID = clientSockfdToSessionID(i);
                            if(sessionID != SESSION_NOT_FOUND)
                            {
                                auto session = sessionList.find(sessionID);
                                session->second.erase(i);
                                if(session->second.empty())
                                {
                                    sessionList.erase(session);
                                }
                            }
                        }
                        else perror("recv");
                        
                        close(i);
                        FD_CLR(i, &master); // remove from master set
                    }
                    
                    else // We got some data from a client
                    {

                        struct message packet = messageFromPacket(buf);
                        string sessionID;
                        stringstream ss(packet.data);
                        
                        switch(packet.type)
                        {
                            case JOIN:
                                
                                ss >> sessionID;
                                
                                if(joinSession(i, packet.data))
                                {
                                    cout << "Client '" << packet.source << "' joined session '" 
                                         << sessionID  << "'" << endl;
                                }
                                else
                                {
                                    cout << "Client '" << packet.source << "' could not join session '" 
                                         << sessionID << "'" << endl;
                                }
                                break;
                                
                                
                            case LEAVE_SESS:
                                if (leaveSession(i))
                                {
                                    cout << "Client '" << packet.source << "' has left session" << endl;
                                         
                                }
                                else
                                {
                                    cout << "Client '" << packet.source << "' is not in a session" 
                                         << endl;
                                }
                                break;
                                
                            case NEW_SESS:
                                
                                ss >> sessionID;
                                
                                if(createSession(i, packet.data))
                                {
                                    cout << "New session '" << sessionID << "' created for client "
                                         << packet.source << endl;
                                }
                                else
                                {
                                    cout << "Session '" << sessionID << "' cannot be created" 
                                         << endl;
                                }     
                                break;
                            case MESSAGE:
                            {
                                // Get list of clients connected in the session with the sender
                                string sessionID = clientSockfdToSessionID(i);
                                unordered_set<int> session;
                                if(sessionID != SESSION_NOT_FOUND)
                                {
                                    session = sessionList.find(sessionID)->second;
                                }
                                
                                packet.data.erase(0, 1); // Remove extra space
                                
                                // Send message to all clients in the session (excluding the sender)
                                for(auto const & clientSockfd : session)
                                {
                                    if(clientSockfd != i) sendToClient(&packet, clientSockfd);
                                }
                                
                                cout << "Message sent to session '" << sessionID << "'" << endl;
                                break;
                            }
                            case DIRMESSAGE:
                            {
                                if(!sendDirectMessage(packet, i))
                                {
                                    cout << "Direct message not sent" << endl;
                                }
                                else
                                {
                                    cout << "Direct message sent" << endl;
                                }
                            }
                            case QUERY:
                                createList(i);
                                break;
                            default:
                                break;
                        }
                    }
                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END while

    return 0;
}
