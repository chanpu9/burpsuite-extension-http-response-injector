# Burpsuite Extension - HTTP Response Injector

This extension will inject HTTP responses with data. This can be useful for things such as inserting a keylogger into a vulnerable site.


# What this plugin does
The builtin "Match and Replace" feature applies a simple regexp to every request/response
No way to 
   1. restrict to scope 
   2. do complex filtering 
   3. target specific IP addresses

This extension allows to inject some JavaScript if:
 - the client wasn't already infected (3 ways to manage duplicates)
 - the page URL is in scope (or not)
 - the response body matches a specific string
 - the response has the desired MIME type
 The target is usually externally MITM-ed via ARP, DNS or WPAD attacks

 Sample Use cases:
 1. load a client side-side attack in an iframe (like Metasploit Browser AutoPwn)
 2. inject BeEF hooks
 3. load Firebug Lite in a mobile browser like iPad and iPhone
 4. add a <img> tag pointing to a SMB share in order to capture NTLM hashes

# Installation

In order to use burp extensions, burpsuite expects you to import a .jar file. In order to generate a jar file you can use maven and run the following command

```
mvn clean install
```

This will create a `target` directory which will contain a .zip file wich you can then import into burpsuits _extensions_ tab.

# Credits

This project started out as a java conversion of the python equivalent I came across at  [https://github.com/libcrack/pentest/blob/master/burpsuite/extensions/HTTPInjector.py].
