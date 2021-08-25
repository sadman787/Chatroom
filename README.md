# Multi-Party Text Conferencing Lab

This lab contains two separate programs, one being the client that can connect to a server and send messages to other clients and a server that handles all incoming messages from the clients.


## Usage


### Server

To run the server, type in the terminal:

```
server <server_port_number>
```

### Client

To run the client, type in the terminal:

```
client
```

The valid usernames and passwords are hardcoded in the server source code.


## Available Commands

The commands a user can enter are:

```
/login <client ID> <password> <server IP> <server port>
/logout
/joinsession <name> <password>
/leavesession
/createsession <name> <password>
/directmessage <user> "message"
/list
/quit
<text> // Sends text to the current session
```


## Extra Features

### Direct Messaging

Clients are able to send private messages to other clients whether or not they are inside a chat session for privacy purposes. To send a direct message, type in the terminal:

```
/directmessage <user> "message"
```

### Session Password Protection

Creating and joining a session requires a password for privacy and security purposes. To create a password-protected session, type in the terminal:

```
/createsession <name> <password>
```

Similarly, to join a password-protected session, type in the terminal:

```
/joinsession <name> <password>
```

