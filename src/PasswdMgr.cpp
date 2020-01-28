#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"
#include <random>

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;
std::cout << "start check user\n";
   bool result = findUser(name, passwd, salt);
std::cout << "end check user\n";
   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash(hashlen); // hash from the password file
   std::vector<uint8_t> passhash(hashlen); // hash derived from the parameter passwd
   std::vector<uint8_t> salt(saltlen);
std::cout << "start check password\n";
   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   hashArgon2(passhash, salt, passwd, &salt);

std::cout << "userhash " << userhash.data() << "\n";
std::cout << "passhash " << passhash.data() << "\n";

std::cout << "end check password\n";
   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {

   // Insert your insane code here
   // read everything out into a buf..then change and then rewrite everything

   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!
   int newlineCount = 0;
   std::string buf;
std::cout << "start read user\n";

   int nameCount = pwfile.readStr(name);
   if(nameCount == -1)
      throw pwfile_error("Error reading from passwd file");

   if(nameCount == 0)
      return false;

   uint8_t newline;
   int hashCount = pwfile.readBytes<uint8_t>(hash, hashlen);
   if(hashCount == -1)
      throw pwfile_error("Error reading passwd file");

   int saltCount = pwfile.readBytes<uint8_t>(salt, saltlen);
   if(saltCount == -1)
      throw pwfile_error("Error reading passwd file");

   newlineCount = pwfile.readByte(newline);
   if(newlineCount == -1)
      throw pwfile_error("Error reading passwd file");

std::cout << "end read user\n";
   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
std::cout << "start write user\n";
   int results, nameCount, hashCount, saltCount, newlineCount = 0;
   std::string newline("\n");
   // Insert your wild code here!

   std::cout << hash.size() << "\n";

   nameCount = pwfile.writeFD(name);
   if(nameCount == -1)
      throw pwfile_error("Error writting to passwd file");

   results += nameCount;

   newlineCount = pwfile.writeFD(newline);
   if(newlineCount == -1)
      throw pwfile_error("Error writting to passwd file");
   
   results += newlineCount;

   hashCount = pwfile.writeBytes(hash);
   results += hashCount;

   saltCount = pwfile.writeBytes(salt);
   results += saltCount;

   newlineCount = pwfile.writeFD(newline);
   if(newlineCount == -1)
      throw pwfile_error("Error writting to passwd file");

   results += newlineCount;
std::cout << "end write user\n";
   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {
std::cout << "start find user\n";
   FileFD pwfile(_pwd_file.c_str());
   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
std::cout << "end find user\n";
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/

void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!
   uint32_t t_cost = 2;            // 1-pass computation
   uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
   uint32_t parallelism = 1;       // number of threads and lanes
std::cout << "start hash\n";
   uint8_t saltArr[saltlen];
   uint8_t hashArr[hashlen];

   if(in_salt == NULL) {
      std::vector<uint8_t> insalt(saltlen);
      insalt = generateSalt();
      for(int i = 0; i < saltlen; i++) {
         saltArr[i] = insalt.at(i);
      }
   } else {
      for(int i = 0; i < saltlen; i++) {
         saltArr[i] = in_salt->at(i);
      }
   }

   
   //thwor std::runtime_error("passed in salt is not right size")

   // high-level API
   //argon2i_hash_raw(t_cost, m_cost, parallelism, in_passwd, strlen(in_passwd), static_cast<void*>(ret_salt.data()), saltlen, static_cast<void*>(ret_hash.data()), hashlen);
   argon2i_hash_raw(t_cost, m_cost, parallelism, in_passwd, strlen(in_passwd), saltArr, saltlen, hashArr, hashlen);

   for(int i = 0; i < hashlen; i++) {
      ret_hash.at(i) = hashArr[i];
   }

   for(int i = 0; i < saltlen; i++) {
      ret_salt.at(i) = saltArr[i];
   }
std::cout << "end hash\n";
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!
   std::vector<uint8_t> passhash(hashlen);
   std::vector<uint8_t> salt(saltlen);
   std::vector<uint8_t> insalt(saltlen);
std::cout << "start add user\n";
   if (checkUser(name)) {
      std::cout << "user was already found in passwd file... \n";
      return;
   }

   insalt = generateSalt();
   hashArgon2(passhash, salt, passwd, &insalt);

   FileFD pwfile(_pwd_file.c_str());
   if (!pwfile.openFile(FileFD::appendfd))
      throw pwfile_error("Could not open passwd file for writting");

   std::string nameString(name);

std::cout << passhash.data() << "\n";
std::cout << nameString;

   writeUser(pwfile, nameString, passhash, insalt);

std::cout << "end add user\n";
}

/****************************************************************************************************
 * generateSalt - Generates a random salt to be used in password hashing
 * 
 *                Returns: std char vector of size 16
 *
 ****************************************************************************************************/

std::vector<uint8_t> PasswdMgr::generateSalt() {
   std::mt19937 rng(time(0));
   //std::uniform_int_distribution<int> gen(33, 126);
   std::uniform_int_distribution<int> gen(65, 90);
   std::vector<uint8_t> salt;

   for(int i = 0; i < 16; i++){
      uint8_t c = gen(rng);
      salt.push_back(c);
   }

   return salt;
}
