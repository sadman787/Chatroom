/* 
 * File:   client.cpp
 * Author: anileeli
 *
 * Created on November 12, 2018, 8:46 PM
 */

#include <cstdlib>
#include <string>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <arpa/inet.h>
#include <iterator>

#define CMD_LOGIN      "/login"
#define CMD_LOGOUT     "/logout"
#define CMD_JOINSESS   "/joinsession"
#define CMD_LEAVESESS  "/leavesession"
#define CMD_CREATESESS "/createsession"
#define CMD_DIRMESSAGE "/directmessage" 
#define CMD_LIST       "/list"
#define CMD_QUIT       "/quit"

#define SESSION_NOT_FOUND "NoSessionFound"

#define MAXDATASIZE 1380 // max number of bytes we can get at once

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
// Note: when message is stringified, the delimiter between fields is " "
struct message {
    unsigned int type;
    unsigned int size;
    string source;
    string data;
};


// Contains connection information about the client and server
struct connectionDetails {
    string clientID;
    string clientPassword;
    string serverIP;
    string serverPort;
};


// GLOBAL VARIABLES
int sockfd = -1;                // Socket used to communicate with server
struct connectionDetails login; // Holds login details pertaining to this client
bool loggedIn = false;          // Keep track of if this client is logged in
bool inSession = false;         // Keep track of it this client is in a session


// Get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}


// Create a packet string from a message structure
string stringifyMessage(const struct message* data)
{
    string dataStr = to_string(data->type) + " " + to_string(data->size) 
                     + " " + data->source + " " + data->data;
    return dataStr;
}


// Sends a message to server in the following format:
//   message = "<type> <data_size> <source> <data>"
// Returns true if message is successfully sent
bool sendToServer(struct message *data)
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


// Sends login info to server and checks server's response
// Returns true if login is successful
bool requestLogin(struct connectionDetails login)
{
    char buffer[MAXDATASIZE];
    int numBytes, response;
    struct message info;
    info.type = LOGIN;
    info.size = login.clientPassword.length() + 1;
    info.source = login.clientID;
    info.data = login.clientPassword;
        
    // Sends login request to server
    if(!sendToServer(&info)){
        return false;
    }
    
    // Server response
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return false;
    }
    
    // Checking packet type
    string s(buffer), temp, data;
    stringstream ss(s);
    ss >> response >> temp >> temp >> data;
    
    if(response == LO_NAK)
    {
        // Get the rest of the error message
        string restOfData;
        getline(ss, restOfData);
        data += restOfData;
        
        cout << "Error: " << data << endl;
        return false;
    }
    else if(response == LO_ACK) 
    {
        cout << "Login successful!" << endl;
        return true;
    } 
    else
    {
        cout << "login: unknown message type received" << endl;
        return false;
    }
}


// Sends the logout request to the server
void logout()
{
    struct message info;
    info.type = EXIT;
    info.size = 0;
    info.source = login.clientID;
    info.data = "";
    
    if(sendToServer(&info)) cout << "Logout successful!" << endl;
}


// Requests to join a session in the server and checks server's response
// Returns true if session is joined
bool requestJoinSession(string sessionID, string sessionPassword)
{
    char buffer[MAXDATASIZE];
    int numBytes, response;
    struct message joinSession;
    joinSession.type = JOIN;
    joinSession.size = sessionID.length() + 1;
    joinSession.source = login.clientID;
    joinSession.data = sessionID + " " + sessionPassword;
    
    // Sends login request to server
    if(!sendToServer(&joinSession)){
        return false;
    }
    
    // Server response
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return false;
    }
    
    // Checking packet type
    string s(buffer), temp, data;
    stringstream ss(s);
    ss >> response >> temp >> temp >> data;
    
    if(response == JN_NAK) 
    {
        // Get the rest of the error message
        string restOfData;
        getline(ss, restOfData);
        data += restOfData;
        
        cout << "Error: " << data << endl;
        return false;
    }
    else if(response == JN_ACK)
    {
        cout << "Session '" << data << "' joined!" << endl;
        return true;
    }
    else
    {
        cout << "joinsession: unknown message type received" << endl;
        return false;
    }
}


// Asks server to remove it from the current session and checks server's response
// Returns true if session is exited
bool requestLeaveSession()
{
    char buffer[MAXDATASIZE];
    int numBytes, response;
    struct message leaveSession;
    leaveSession.type = LEAVE_SESS;
    leaveSession.size = 0;
    leaveSession.source = login.clientID;
    leaveSession.data = "";
    
    // Sends login request to server
    if(!sendToServer(&leaveSession)){
        return false;
    }
    
    // Server response
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return false;
    }
        
    string s(buffer), temp, data;
    stringstream ss(s);
    ss >> response >> temp >> temp >> data;

    
    if (response == LS_NAK)
    {
        // Get the rest of the error message
        string restOfData;
        getline(ss, restOfData);
        data += restOfData;
        
        cout << "Error: " << data << endl;
        return false;
    }
    else if (response == LS_ACK)
    {
        cout << "Exited session '" << data << "'!" << endl;
        return true;
    }
    else
    {
        cout << "leavesession: unknown message type received" << endl;
        return false;
    }
}


// Requests to make a new session and checks the server's response
// Returns true if session was successfully created
bool requestNewSession(string sessionID, string sessionPassword)
{
    char buffer[MAXDATASIZE];
    int numBytes, response;
    struct message newSession;
    newSession.type = NEW_SESS;
    newSession.size = sessionID.length() + 1;
    newSession.source = login.clientID;
    newSession.data = sessionID + " " + sessionPassword;
    
    // Sends login request to server
    if(!sendToServer(&newSession)){
        return false;
    }
    
    // Server response
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return false;
    }
        
    // Checking packet type
    string s(buffer), temp, data;
    stringstream ss(s);
    ss >> response >> temp >> temp >> data;

    if(response == NS_NAK) 
    {
        // Get the rest of the error message
        string restOfData;
        getline(ss, restOfData);
        data += restOfData;
        
        cout << "Error: " << data << endl;
        return false;
    }
    
    else if(response == NS_ACK)
    {
        
        cout << "Session '" << data << "' created!" << endl;
        return true;
    }
    else
    {
        cout << "newsession: unknown message type received" << endl;
        return false;
    }
}


// Prints out list of connected clients and available sessions
void printClientSessionList(string buffer)
{
    // Get rid of type, data_size, and source, leaving just the list of clients and sessions
    stringstream ss(buffer);
    string temp;
    ss >> temp >> temp >> temp;

    // Printing list of clients and sessions
    string data;
    
    cout << endl;
    while(ss >> data)
    {
        if(data == "Clients" || data == "Available") 
        {
            if (data == "Available") cout << endl;
            cout << data;
            ss >> data;
        }
        cout << " " << data << endl;
    }
   
}


// Sends a request to return the list of active clients and available sessions
// Returns session list if bool is true
pair<bool, string> requestClientSessionList()
{
    int numBytes, response;
    char buffer[MAXDATASIZE];
    
    // Prepare message
    struct message info;
    info.type = QUERY;
    info.size = 0;
    info.source = login.clientID;
    info.data = "";
    
    if(!sendToServer(&info)){
        cout << "List unavailable!" << endl;
        return make_pair(false, "NoList");
    }
    
    // Server response
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return make_pair(false, "NoList");
    }
    
    // Checking packet type
    string s(buffer);
    stringstream ss(s);
    ss >> response;
    
    if(response != QU_ACK)
    {
        cout << "List unavailable!" << endl;
        return make_pair(false, "NoList");
    }
    // List received, return it
    else
    {
        return make_pair(true, s);
    }
}


// Creates connection with server and returns socket file descriptor that
// describes the connection
int createConnection()
{
    int newSockFD, rv;
    struct addrinfo hints, *servinfo, *p;
    char s[INET6_ADDRSTRLEN];
    
    // If invalid/incomplete login information provided
    if(login.clientID.empty() == true || login.clientPassword.empty() == true ||
       login.serverIP.empty() == true || login.serverPort.empty() == true)
    {
        cout << "Invalid login info!" << endl;
    }
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(login.serverIP.c_str(), login.serverPort.c_str(), &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // Loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((newSockFD = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("client: socket");
            continue;
        }

        if (connect(newSockFD, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(newSockFD);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "client: failed to connect\n");
        return -1;
    }

    //Retrieves IP address from the server that is currently being connected to
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *) p->ai_addr),
            s, sizeof s);
    printf("Trying to connect to server at %s\n", s);

    return newSockFD;
}


void sendMessage(string message)
{
    struct message sessMessage;
    sessMessage.type = MESSAGE;
    sessMessage.size = message.length() + 1;
    sessMessage.source = login.clientID;
    sessMessage.data = message;
    
    if(!sendToServer(&sessMessage)) cout << "Message not sent!" << endl;
}


// Returns the number of arguments in a string
unsigned int countNumArguments(std::string const& str)
{
    stringstream stream(str);
    return distance(istream_iterator<string>(stream), istream_iterator<string>());
}


bool sendDirectMessage(string receiverID, string message)
{
    char buffer[MAXDATASIZE];
    int numBytes, response;
    struct message dirMessage;
    dirMessage.type = DIRMESSAGE;
    dirMessage.source = login.clientID;
    dirMessage.data = receiverID + " " + message;
    dirMessage.size = dirMessage.data.length() + 1;
    
    if(!sendToServer(&dirMessage)) cout << "Message not sent!" << endl;
    
    // Server response
    if((numBytes = recv(sockfd, buffer, MAXDATASIZE, 0)) == -1)
    {
        perror("recv");
        return false;
    }
        
    string s(buffer), temp, data;
    stringstream ss(s);
    ss >> response >> temp >> temp >> data;
    
    if (response == DMESS_NAK)
    {
        // Get the rest of the error message
        string restOfData;
        getline(ss, restOfData);
        data += restOfData;
        
        cout << "Error: " << data << endl;
        return false;
    }
    else if (response == DMESS_ACK) return true;
    else
    {
        cout << "directmessage: unknown message type received" << endl;
        return false;
    }
}

int main(int argc, char** argv)
{
    if (argc != 1)
    {
        fprintf(stderr, "usage: client\n");
        exit(1);
    }
    
    fd_set master, read_fds; // WIll hold descriptors for connection and stdin
    int fdmax;
    
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &master); // File descriptor for standard input
    
    fdmax = STDIN_FILENO;

    /********************** GET LOGIN/CONNECTION INFO *************************/

    cout << "\nPlease enter login information in the following format:\n"
            "/login <client_id> <password> <server-IP> <server-port>\n" << endl;

    while(1)
    {        
        read_fds = master; // copy master list
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1)
        {
            perror("select");
            exit(4);
        }

        for(int i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds))
            {
                if(i == sockfd) // Message from the server
                {
                    int nbytes;
                    char buf[MAXDATASIZE];

                    // Got error or connection closed by server
                    if ((nbytes = recv(i, buf, MAXDATASIZE, 0)) <= 0)
                    {
                        if (nbytes == 0) // Connection closed
                        {
                            cout << "Server closed! Goodbye!" << endl;
                        }
                        else perror("recv");
                        
                        close(i);
                        FD_CLR(i, &master); // remove from master set
                        return 0;
                    }
                    else // Received data
                    {
                        string received(buf), size, source, message;
                        int type;
                        stringstream ss(received);
                        ss >> type >> size >> source;
                        
                        getline(ss, message);
                        message.erase(0, 1); // Remove extra space from getline

                        if(type == MESSAGE)
                            cout << source << ": " << message << endl;
                        else if(type == DIRMESSAGE)
                            cout << source << "(DM): " << message << endl;
                    }
                }
                else // Only 2 descriptors in set, so this is stdin
                {
                    // Create stringstream to extract login input from user
                    string input, command;
                    getline(cin, input);
                    stringstream ss(input);

                    ss >> command;

                    if(command == CMD_LOGIN)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 4)
                        {
                            cout << "Usage: /login <username> <password> <server IP> <server port>" << endl;
                        }
                        else if(!loggedIn)
                        {
                            // Get login information
                            ss >> login.clientID >> login.clientPassword
                               >> login.serverIP >> login.serverPort;
                            
                            // Create connection and get file descriptor
                            sockfd = createConnection();

                            // If connection created and login info sent successfully
                            if(sockfd != -1 && requestLogin(login))
                            {
                                FD_SET(sockfd, &master);
                                if(sockfd > fdmax) fdmax = sockfd;
                                loggedIn = true;
                            }
                            else
                            {
                                close(sockfd);
                                sockfd = -1;
                            }
                        }
                        else cout << "Already logged in!" << endl;
                        cout << endl;
                    }
                    else if(command == CMD_LOGOUT)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 0)
                        {
                            cout << "Usage: /logout" << endl;
                        }
                        else if(inSession)
                        {
                            cout << "Please leave the session before logging out!" << endl;
                        }
                        else if(loggedIn)
                        {
                            logout();
                            loggedIn = false;

                            cout << "Closing connection" << endl;
                            close(sockfd);
                            FD_CLR(sockfd, &master); // remove from master set
                        }
                        else cout << "Please login" << endl;
                        cout << endl;
                    }
                    else if(command == CMD_QUIT)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 0)
                        {
                            cout << "Usage: /quit" << endl;
                        }
                        else if(inSession)
                        {
                            cout << "Please leave the session before quitting!" << endl;
                        }
                        else if(loggedIn)
                        {
                            logout();
                            loggedIn = false;

                            cout << "Closing connection" << endl;
                            close(sockfd);
                            FD_CLR(sockfd, &master); // remove from master set

                        }
                        exit(1);
                        cout << endl;
                    }
                    else if(!loggedIn) // Cannot enter any other command before logging in
                    {
                        cout << "Please login" << endl;
                        cout << endl;
                    }
                    else if(command == CMD_JOINSESS)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 2)
                        {
                            cout << "Usage: /joinsession <name> <password>" << endl;
                        }
                        else
                        {
                            string sessionID, sessionPassword;
                            ss >> sessionID >> sessionPassword;
                            if(requestJoinSession(sessionID, sessionPassword))
                            {
                                inSession = true;
                            }
                        }
                        cout << endl;
                    }
                    else if(command == CMD_LEAVESESS)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 0)
                        {
                            cout << "Usage: /leavesession" << endl;
                        }
                        else if(requestLeaveSession())
                        {
                            inSession = false;
                        }
                        cout << endl;
                    }
                    else if (command == CMD_CREATESESS)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 2)
                        {
                            cout << "Usage: /createsession <name> <password>" << endl;
                        }
                        else
                        {
                            string sessionID, sessionPassword;
                            ss >> sessionID >> sessionPassword;
                            if(requestNewSession(sessionID, sessionPassword))
                            {
                                inSession = true;
                            }
                        }
                        cout << endl;
                    }
                    else if(command == CMD_LIST)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments != 0)
                        {
                            cout << "Usage: /list" << endl;
                        }
                        else if(inSession)
                        {
                            cout << "Please leave the session before listing connected "
                                    "clients and available sessions!" << endl;
                        }
                        else
                        {
                            auto res = requestClientSessionList();
                            if(res.first == true) printClientSessionList(res.second);
                        }
                        cout << endl;
                    }
                    else if(command == CMD_DIRMESSAGE)
                    {
                        unsigned int numArguments = countNumArguments(input) - 1;
                        if(numArguments == 0)
                        {
                            cout << "Usage: /directmessage <user> \"message\"" << endl;
                        }
                        else
                        {
                            string receiverID, message; 
                            ss >> receiverID; // Client ID receiving the message
                            getline(ss, message);
                            
                            // Find the quotations that denote the message
                            size_t startOfMessage = message.find_first_of("\"");
                            size_t endOfMessage = message.find_last_of("\"");
                           
                            // Error checking on the message structure
                            if(startOfMessage == string::npos || endOfMessage == string::npos || startOfMessage == endOfMessage)
                            {
                                cout << "Please put your message within double quotation marks!" << endl;
                            }
                            else if(endOfMessage - startOfMessage == 1)
                            {
                                cout << "Cannot send empty message!" << endl;
                            }
                            else if(message.substr(endOfMessage+1).find_first_not_of("\n\t\r ") != string::npos)
                            {
                                cout << "Please don't enter characters after the message!" << endl;
                            }
                            else
                            {
                                // Message is valid, remove quotes and try sending to receiving client
                                message = message.substr(startOfMessage + 1, endOfMessage - startOfMessage - 1);
                                sendDirectMessage(receiverID, message);
                            }
                        }
                        cout << endl;
                    }
                    else
                    {
                        if(!inSession)
                        {
                            cout << "Unknown command" << endl;
                            cout << endl;
                        }
                        else
                        {
                            // Send message to the server to send to all clients in the session
                            string message;
                            getline(ss, message);
                            message.insert(0, command); // Command is part of the message
                            
                            sendMessage(message);
                        }
                    }
                }
            }
        }
    }
    return 0;
}