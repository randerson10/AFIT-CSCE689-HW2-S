#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <strings.h>
#include <vector>
#include <iostream>
#include <memory>
#include <sstream>
#include "TCPServer.h"
#include "strfuncts.h"


const char serverfilename[] = "server.log";

TCPServer::TCPServer() {//:_server_log(serverfilename) {

}


TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   struct sockaddr_in servaddr;

   log(1);

   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::listenSvr() {

   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;
   int num_read = 0;

   // Start the server socket listening
   _sockfd.listenFD(5);

    
   while (online) {
      struct sockaddr_in cliaddr;
      socklen_t len = sizeof(cliaddr);

      if (_sockfd.hasData()) {
         TCPConn *new_conn = new TCPConn();
         if (!new_conn->accept(_sockfd)) {
            // _server_log.strerrLog("Data received on socket but failed to accept.");
            continue;
         }
         std::cout << "***Got a connection***\n";

         // Get their IP Address string to use in logging
         std::string ipaddr_str;
         new_conn->getIPAddrStr(ipaddr_str);

         //if their IP is not on the whitelist don't allow them to connect
         if(!new_conn->isIPAllowed(ipaddr_str)) {
            const char *msg = "Your IP is blocked!\n";
            new_conn->sendText(msg);
            new_conn->disconnect();
            log(2, ipaddr_str);
            continue;
         }

         _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));
         log(3, ipaddr_str);
         

         new_conn->sendText("Welcome to the CSCE 689 Server!\n");

         // Change this later
         new_conn->startAuthentication();
      }

      // Loop through our connections, handling them
      std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
      while (tptr != _connlist.end())
      {
         // If the user lost connection
         if (!(*tptr)->isConnected()) {
            // Log it

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue;
         }

         // Process any user inputs
         (*tptr)->handleConnection();

         // Increment our iterator
         tptr++;
      }

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   } 


   
}


/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {

   _sockfd.closeFD();
}

/**********************************************************************************************
 * log - Logs a message to the server log.
 * 
 *    Params: option - int representing the type of log message to log
 *                ip - IP address of this connection
 * 
 *    Throws: logfile_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::log(int option, const std::string ip) {
   FileFD logfile(serverfilename);
   if (!logfile.openFile(FileFD::appendfd))
      throw logfile_error("Could not open log file for writting");

   std::string msg = getTime();

   switch(option){
      case 1: //server startup
         msg += ": Server started\n";
         break;
      case 2: //new conn not on whitelist
         msg += ": Connection from IP that is not on whitelist. IP: [" + ip + "]\n";
         break;
      case 3: //new conn on whitelist
         msg += ": Connection from IP that is on whitelist. IP: [" + ip + "]\n";
         break;
      default:
         std::cout << "Error in log switch\n";
         break;
   }
 
   int results = logfile.writeFD(msg);
   if(results == -1)
      throw logfile_error("Error writting to log file");

   logfile.closeFD();
}

