#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include "TCPConn.h"
#include "strfuncts.h"
#include "FileDesc.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";
const char serverfilename[] = "server.log";
const char whitelistfilename[] = "whitelist";

TCPConn::TCPConn() : _pwm(pwdfilename) { // LogMgr &server_log):_server_log(server_log) {
   
}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   // Skipping this for now
   _status = s_username;

   _connfd.writeFD("Username: "); 
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();

            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Insert your mind-blowing code here
   std::string uname;

   if (!getUserInput(uname))
      return;
   
   clrNewlines(uname);

   if(!_pwm.checkUser(uname.data())) {
      _username = uname;
      _connfd.writeFD("Username not found...disconnecting\n");
      log(4);
      disconnect();
      log(7);
   }
   _username = uname;
   _status = s_passwd;

}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Insert your astounding code here
   std::string password;
   _connfd.writeFD("Password: "); 

   if (!getUserInput(password))
      return;
   
   clrNewlines(password);

   while(_pwd_attempts < max_attempts) {
      if(!_pwm.checkPasswd(_username.data(), password.data())) {
         if(_pwd_attempts == 0) {
            _connfd.writeFD("Incorrect password...try again\n");
            _connfd.writeFD("Password: ");
            if (!getUserInput(password))
               return;
         }
         else {
            _connfd.writeFD("Incorrect password...disconnecting\n");
            log(5);
            disconnect();
            log(7);
            return;
         }
         _pwd_attempts++;
      } else {
         break;
      }
   }

   _status = s_menu;
   _pwd_attempts = 0;
   sendMenu();
   log(6);
}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   // Insert your amazing code here
   std::string passwd1, passwd2;

   if(_status == s_changepwd) {
      _connfd.writeFD("New Password: ");
      if (!getUserInput(_newpwd))
         return;
   
      clrNewlines(_newpwd);
      _status = s_confirmpwd;
      return;
   } else if(_status == s_confirmpwd) {
      _connfd.writeFD("Confirm Password: ");
      if (!getUserInput(passwd2))
         return;
   
      clrNewlines(passwd2);
      if (passwd2.compare(_newpwd) != 0){
         _connfd.writeFD("Passwords do not match\n"); 
         _status = s_changepwd;
         return;
      }

      std::cout << "passwords match\n";

      _status = s_menu;

   }

}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   // Don't be lazy and use my outputs--make your own!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello back!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
      disconnect();
      log(7);
   } else if (cmd.compare("passwd") == 0) {
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "You want a prediction about the weather? You're asking the wrong Phil.\n";
      msg += "I'm going to give you a prediction about this winter. It's going to be\n";
      msg += "cold, it's going to be dark and it's going to last you for the rest of\n";
      msg += "your lives!\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("42\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("That seems like a terrible idea.\n");
   } else if (cmd.compare("4") == 0) {

   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("I'm singing, I'm in a computer and I'm siiiingiiiing! I'm in a\n");
      _connfd.writeFD("computer and I'm siiiiiiinnnggiiinnggg!\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Make this your own!
   menustr += "Available choices: \n";
   menustr += "  1). Provide weather report.\n";
   menustr += "  2). Learn the secret of the universe.\n";
   menustr += "  3). Play global thermonuclear war\n";
   menustr += "  4). Do nothing.\n";
   menustr += "  5). Sing. Sing a song. Make it simple, to last the whole day long.\n\n";
   menustr += "Other commands: \n";
   menustr += "  Hello - self-explanatory\n";
   menustr += "  Passwd - change your password\n";
   menustr += "  Menu - display this menu\n";
   menustr += "  Exit - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/

void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

/**********************************************************************************************
 * isIPAllowed - Searches the white list file for a given IP.
 * 
 *    Params: ip - IP to search for.
 * 
 *    Returns: true if the IP was found in the white list file, false otherwise.
 * 
 *    Throws: whitelistfile_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::isIPAllowed(std::string ip) {
   std::string buf = "";
   int count = 0;
   FileFD whitelistfile(whitelistfilename);

   if(!whitelistfile.openFile(FileFD::readfd)) {
      throw whitelistfile_error("Could not open whitelist file for reading");
   }
   
   while((count = whitelistfile.readStr(buf)) != 0) {
      if(count == -1){
         whitelistfile.closeFD();
         throw whitelistfile_error("Error reading from whitelist file");
      }

      if(ip.compare(buf) == 0) {
         whitelistfile.closeFD();
         return true;
      }
   }
   whitelistfile.closeFD();
   return false;
}

/**********************************************************************************************
 * log - Logs a message to the server log.
 * 
 *    Params: msg - int representing the type of log message to log
 * 
 *    Throws: logfile_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::log(int option) {
   FileFD logfile(serverfilename);
   if (!logfile.openFile(FileFD::appendfd))
      throw logfile_error("Could not open log file for writting");

   std::string msg = getTime();
   std::string ip;

   switch(option){
      case 4: //bad username
         _connfd.getIPAddrStr(ip);
         msg += ": Username not recognized. Username: [" + _username + "] IP: [" + ip + "]\n";
         break;
      case 5: //failed to input password twice
         _connfd.getIPAddrStr(ip);
         msg += ": Failed to enter correct password. Username: [" + _username + "] IP: [" + ip + "]\n";
         break;
      case 6: //successful login
         _connfd.getIPAddrStr(ip);
         msg += ": Successful login. Username: [" + _username + "] IP: [" + ip + "]\n";
         break;
      case 7: //disconnect
         _connfd.getIPAddrStr(ip);
         msg += ": User disconnected. Username: [" + _username + "] IP: [" + ip + "]\n";
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