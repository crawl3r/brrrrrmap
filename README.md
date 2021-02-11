# brrrrrmap  
  
A wrapper for nmap to pass multiple hosts in and receive the output + the identified low hanging fruit. In theory, it should help give you some next steps and easy reportable items.  
  
Currently:  
- takes a list of hosts from stdin and performs a quick initial scan  
- reacts to initial and follows up a secondary full port range scan  
  
Next steps:  
- Perform a deeper scan against the identified open ports (look for banners, vulns, etc)  
- Analyse the results and prompt the user with possible next steps and easy pentest reportables (low hanging fruit)  
  
## Installation  
  
```  
go get github.com/crawl3r/brrrrrmap  
```  
  
## Usage  
      
```  
cat hosts.txt | ./brrrrrmap  
```   
  
## License  
  
I'm just a simple skid. Licensing isn't a big issue to me, I post things that I find helpful online in the hope that others can:  
A) learn from the code  
B) find use with the code or  
C) need to just have a laugh at something to make themselves feel better  
  
Either way, if this helped you - cool :)  