# Sécuriser une base de données

### Separate the Database and Web Servers

Keep the database server separate from the web server. When installing most web software, the database is created for you. To make things easy, this database is created on the same server where the application itself is being installed, the web server. Unfortunately, this makes access to the data all too easy for an attacker to access. If they are able to crack the administrator account for the web server, the data is readily available to them.

Instead, a database should reside on a separate database server located behind a firewall, not in the [DMZ](https://fr.wikipedia.org/wiki/Zone_d%C3%A9militaris%C3%A9e_(informatique)) with the web server. While this makes for a more complicated setup, the security benefits are well worth the effort.
___
### Encrypt Stored Files & Your Backups

Encrypt stored files. WhiteHat security estimates that 83 percent of all web sites are vulnerable to at least one form of attack. The stored files of a web application often contains information about the databases the software needs to connect to. This information, if stored in plain text like many default installations do, provide the keys an attacker needs to access sensitive data.

Encrypt back-up files. Not all data theft happens as a result of an outside attack. Sometimes, it’s the people we trust most that are the attackers.

**Tools**
- bcrypt 
___
### Use a WAF

Employ  [web application firewalls](http://www.applicure.com/solutions/web-application-firewall "web application firewalls"). The misconception here might be that protecting the web server has nothing to do with the database. Nothing could be further from the truth. In addition to protecting a site against cross-site scripting vulnerabilities and web site vandalism, a good application firewall can thwart SQL injection attacks as well. By preventing the injection of SQL queries by an attacker, the firewall can help keep sensitive information stored in the database away from prying eyes.

**Tools**


___
### Keep Patches Current

Keep patches current. This is one area where administrators often come up short. Web sites that are rich with third-party applications, widgets, components and various other plug-ins and add-ons can easily find themselves a target to an exploit that should have been patched. This leads us to…
___
### Minimize Use of 3rd Party Apps

Keep third-party applications to a minimum. We all want our web site to be filled with interactive widgets and sidebars filled with cool content, but any app that pulls from the database is a potential threat. Many of these applications are created by hobbyists or programmers who discontinue support for them. Unless they are absolutely necessary, don’t install them.
___
### Don't Use a Shared Server

Avoid using a shared web server if your database holds sensitive information. While it may be easier, and cheaper, to host your site with a hosting provider you are essentially placing the security of your information in the hands of someone else. If you have no other choice, make sure to review their security policies and speak with them about what their responsibilities are should your data become compromised.
___
### Enable Security Controls

Enable security controls on your database. While most databases nowadays will enable security controls by default, it never hurts for you to go through and make sure you check the security controls to see if this was done.

Keep in mind that securing your database means you have to shift your focus from web developer to database administrator. In small businesses, this may mean added responsibilities and additional buy in from management. However, getting everyone on the same page when it comes to security can make a difference between preventing an attack and responding to an attack.

### Permissions
 Apply the  [principle of least privileges](https://en.wikipedia.org/wiki/Principle_of_least_privilege)  - make sure the users are only granted the least amount of permissions needed to do what they have to. Users should be restricted to what their legitimate purpose is. The link above explains this pretty well and it’s an important advice in my opinion.
 ___
 


