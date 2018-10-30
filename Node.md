### L’injection de Commande
Parfois, les développeurs(souvent non expérimentés) se fient aux entrées de l’utilisateur et les utilisent directement dans une commande comme argument par exemple. Ce type d’erreur offre aux hackers plusieurs porte pouvant leur permettre d’exécuter des commandes systèmes sur le serveur où se trouve l’application, d’avoir accès aux fichiers éventuellement confidentiels du serveur, de placer des malware afin de contrôler le serveur distant.

### Principe
Il existe des modules NodeJS qui permet aux développeurs d’exécuter des commandes systèmes. child_process est un exemple.
Ce module comporte une méthode « exec » qui permet d’exécuter des commandes systèmes depuis l’application.
Son utilisation est simple. Il suffit d’appeler la méthode avec un paramètre de type « string » qui représente la commande à exécuter.
Elle peut éventuellement prendre deux autres arguments(les arguments et une fonction de callback).
La commande est non-bloquante c’est à dire qu’elle tournera en background et n’empêchera pas à l’application d’exécuter d’autres tâches.
Par exemple, pour déplacer un fichier dont le chemin est fourni en paramètre par l’utilisateur, on peut utiliser la commande suivante :

```
child_process.exec(
'mv ' + req.body.file_path+ ' destination ' ,
function (err, data) {
console.log(data);
});
```
dans cette situation, un utilisateur mal intentionné peut fournir une valeur égale à « ; rm -rf ».
Ce qui aura comme effet de supprimer tout le dossier de destination avec tous les fichiers qui s’y trouve.
Une conséquence plus lourde serait qu’il ajoute un « / » à la commande(« rm -rf / »).
Ce qui supprimera tous les dossiers du serveur.

### Éviter l’injection de Commande
Première règle : Ne vous fiez jamais aux entrées de l’utilisateur.
Il faut toujours prévoir une couche de validation des données de la part de vos utilisateurs.
Après validation des inputs de l’utilisateur, choisissez une méthode qui ne mélange pas votre commande avec ces inputs.
Vous pouvez par exemple utiliser les méthodes execFile ou spawn à la place de exec.
Ces méthodes force les développeurs à séparer la commande et les arguments.

NB : Si vous ne valider pas d’abord les inputs de l’utilisateur avant d’exécuter ces deux méthodes,
il peut toujours avoir des risques notamment quand l’utilisateur utilise des commandes telles que find, awk etc.

Vous pouvez utiliser le module « joi » pour la validation des inputs.
Vous pouvez également écrire une logique de validation en vous basant sur le principe de whitelist qui consiste à comparer vos inputs à un set de valeurs possibles.

### Redos : un facteur de risque pour les projets JavaScript ?

Le web repose aujourd’hui énormément sur JavaScript et de nombreux projets s’appuient sur un ensemble de dépendances préconçues qu’ils récupèrent sur plusieurs répertoires prévus à cet effet, à l’instar de npm pour node.js. La méthode évite à chaque projet d’avoir à réinventer la roue, mais c’est aussi une source d’inquiétude en termes de sécurité. Des chercheurs de l’université de technologie de Darmstadt en Allemagne alertent sur un risque assez peu évoqué lié à cette évolution : les attaques dites « Redos », qui visent à provoquer une interruption du système en profitant des failles dans la façon dont ces modules JavaScript interprètent les  [expressions régulières.](https://fr.wikipedia.org/wiki/Expression_r%C3%A9guli%C3%A8re)

[](https://fr.wikipedia.org/wiki/Expression_r%C3%A9guli%C3%A8re)![](https://www.zdnet.fr/i/edit/ne/2018/08/code-3337044_640.jpg)

[Comme le rappelle Bleeping Computer](https://www.bleepingcomputer.com/news/security/javascript-web-apps-and-servers-vulnerable-to-redos-attacks/), le principe de l’attaque Redos n’est pas neuf et avait déjà été identifié par le passé en 2012. Il s’agit d’une attaque visant à provoquer un déni de service en exploitant l’envoi d’expression régulière malveillante à la machine, qui mettra un temps important à les traiter et risque donc de paralyser le processus si celles-ci sont envoyées de manière répétée.  [Comme l’expliquent les chercheurs dans l’article](http://mp.binaervarianz.de/ReDoS_TR_Dec2017.pdf), JavaScript est une cible particulièrement vulnérable : « le modèle d’exécution basé sur un seul thread de processeur qui a cours sur les serveurs web basés sur JavaScript en fait une cible particulièrement vulnérable aux attaques de type ReDos. » Et pour démontrer leur argument, les chercheurs ont mis au point  [un outil](https://github.com/sola-da/ReDoS-vulnerabilities)  permettant de détecter la présence de la faille dans des sites en activités.

## Ddos, Redos et Slowloris : un pour tous, tous pour un

« Dans le cadre de cette analyse, nous avons découvert 25 vulnérabilités jusque là inconnues présentes au sein de modules populaires. Nous avons testé 2846 sites web parmi les plus populaires afin de vérifier si ces failles étaient exploitables. Et celles-ci ont été retrouvées dans 339 des sites web » expliquent les chercheurs.

Si les attaques ddos sont aujourd’hui bien connues et fréquemment utilisées par les cybercriminels pour bloquer l’accès à un site web ou à un service, elles ne sont pas les seuls outils leur portée. L’évolution du web, qui a de plus en plus recours à des plateformes JavaScript telles que Node.js, ouvre la voie à de nouvelles attaques, pour l’instant mineures, mais qui pourraient prendre de l’ampleur dans les années à venir. Les chercheurs concluent ainsi leur article en appelant à développer des outils plus perfectionnés afin de détecter et de corriger ce type de faille de sécurité avant qu’elles ne soient effectivement exploitées par des acteurs malveillants.

### Surveiller les failles de Node
https://groups.google.com/forum/#!forum/nodejs-sec

# We’re under attack! 23+ Node.js security best practices

**Collected, curated and written by:**  [Yoni Goldberg](https://www.goldbergyoni.com/), Kyle Martin and Bruno Scheufler

**Tech reviewer:**  [Liran Tal](https://twitter.com/liran_tal)  ( Node.js Security Working Group)

### **Welcome to our comprehensive list of Node.js security best practices which summarizes and curates the top ranked articles and blog posts**

![](https://cdn-images-1.medium.com/max/800/1*REcCEMSBQKJKHJxsD-VzjQ.png)

### Few words before we start

Web attacks explode these days as security comes to the front of the stage. We’ve compiled over 23 Node.js security best practices (+40 other generic security practices) from all top-ranked articles around the globe. The work here is part of our  [Node.js best practices GitHub repository](https://github.com/i0natan/nodebestpractices)  which contains more than 80 Node.js practices.  **Note:** Many items have a  _read more_ link to an elaboration on the topic with code example and other useful information.

[![](https://cdn-images-1.medium.com/max/800/1*itQJfu5RV0MjBonVuUEJjA.png)](https://twitter.com/nodepractices)

Get weekly best practices via our Twitter feed

### 1. Embrace linter security rules

[![](https://cdn-images-1.medium.com/max/800/1*ubIFsp_ql38gviFcGhBL1Q.png)](https://www.owasp.org/index.php/Top_10-2017_A1-Injection)

**TL;DR:**  Make use of security-related linter plugins such as  [eslint-plugin-security](https://github.com/nodesecurity/eslint-plugin-security)  to catch security vulnerabilities and issues as early as possible — while they’re being coded. This can help catching security weaknesses like using eval, invoking a child process or importing a module with a non string literal (e.g. user input). Click ‘Read more’ below to see code examples that will get caught by a security linter

**Otherwise:**  What could have been a straightforward security weakness during development becomes a major issue in production. Also, the project may not follow consistent code security practices, leading to vulnerabilities being introduced, or sensitive secrets committed into remote repositories

[**Read More:** Linter rules](https://github.com/i0natan/nodebestpractices/blob/master/sections/security/lintrules.md)

> Linting doesn’t have to be just a tool to enforce pedantic rules about whitespace, semicolons or eval statements. ESLint provides a powerful framework for eliminating a wide variety of potentially dangerous patterns in your code (regular expressions, input validation, and so on). I think it provides a powerful new tool that’s worthy of consideration by security-conscious JavaScript developers.  **(**[Adam Baldwin](https://medium.com/@adam_baldwin)**)**

> More quotes and code examples here

### 2. Limit concurrent requests using a middleware

[![](https://cdn-images-1.medium.com/max/800/1*egFYL7hd7orI97caxTBKmw.png)](https://www.owasp.org/index.php/Denial_of_Service)

**TL;DR:**  DOS attacks are very popular and relatively easy to conduct. Implement rate limiting using an external service such as cloud load balancers, cloud firewalls, nginx, or (for smaller and less critical apps) a rate limiting middleware (e.g.  [express-rate-limit](https://www.npmjs.com/package/express-rate-limit))

**Otherwise:**  An application could be subject to an attack resulting in a denial of service where real users receive a degraded or unavailable service.

[**Read More:** Implement rate limiting](https://github.com/i0natan/nodebestpractices/blob/master/sections/security/limitrequests.md)

### 3. Extract secrets from config files or use packages to encrypt them

[![](https://cdn-images-1.medium.com/max/800/1*7afKi8CIqClDwZW_UY1xJw.png)](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration)

**TL;DR:**  Never store plain-text secrets in configuration files or source code. Instead, make use of secret-management systems like Vault products, Kubernetes/Docker Secrets, or using environment variables. As a last result, secrets stored in source control must be encrypted and managed (rolling keys, expiring, auditing, etc). Make use of pre-commit/push hooks to prevent committing secrets accidentally

**Otherwise:**  Source control, even for private repositories, can mistakenly be made public, at which point all secrets are exposed. Access to source control for an external party will inadvertently provide access to related systems (databases, apis, services, etc).

[**Read More:** Secret management](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/secretmanagement.md)

### 4. Prevent query injection vulnerabilities with ORM/ODM libraries

[![](https://cdn-images-1.medium.com/max/800/1*ubIFsp_ql38gviFcGhBL1Q.png)](https://www.owasp.org/index.php/Top_10-2017_A1-Injection)

**TL;DR:**  To prevent SQL/NoSQL injection and other malicious attacks,  _always_make use of an ORM/ODM or a database library that escapes data or supports named or indexed parameterized queries, and takes care of validating user input for expected types.  **Never**  just use JavaScript template strings or string concatenation to inject values into queries as this opens your application to a wide spectrum of vulnerabilities. All the reputable Node.js data access libraries (e.g. S[equelize](https://github.com/sequelize/sequelize),  [Knex](https://github.com/tgriesser/knex), m[ongoose](https://github.com/Automattic/mongoose)) have built-in protection agains injection attacks

**Otherwise:**  Unvalidated or unsanitized user input could lead to operator injection when working with MongoDB for NoSQL, and not using a proper sanitization system or ORM will easily allow SQL injection attacks, creating a giant vulnerability.

[**Read More:** Query injection prevention using ORM/ODM libraries](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/ormodmusage.md)

> [⭐](https://github.com/i0natan/nodebestpractices)  Appreciate the effort? P[lease star our project on GitHub](https://github.com/i0natan/nodebestpractices)

### 5. Avoid DOS attacks by explicitly setting when a process should crash

**TL;DR:**  The Node process will crash when errors are not handled. Many best practices even recommend to exit even though an error was caught and got handled. Express, for example, will crash on any asynchronous error — unless you wrap routes with a catch clause. This opens a very sweet attack spot for attackers who recognize what input makes the process crash and repeatedly send the same request. There’s no instant remedy for this but a few techniques can mitigate the pain: Alert with critical severity anytime a process crashes due to an unhandled error, validate the input and avoid crashing the process due to invalid user input, wrap all routes with a catch and consider not to crash when an error originated within a request (as opposed to what happens globally)

**Otherwise:**  This is just an educated guess: given many Node.js applications, if we try passing an empty JSON body to all POST requests — a handful of applications will crash. At that point, we can just repeat sending the same request to take down the applications with ease

### 6. Adjust the HTTP response headers for enhanced security

![](https://cdn-images-1.medium.com/max/800/1*7afKi8CIqClDwZW_UY1xJw.png)

**TL;DR:**  Your application should be using secure headers to prevent attackers from using common attacks like cross-site scripting (XSS), clickjacking and other malicious attacks. These can be configured easily using modules like  [helmet](https://www.npmjs.com/package/helmet).

**Otherwise:**  Attackers could perform direct attacks on your application’s users, leading huge security vulnerabilities

[**Read More:** Using secure headers in your application](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/secureheaders.md)

### 7. Constantly and automatically inspect for vulnerable dependencies

[![](https://cdn-images-1.medium.com/max/800/1*dz7uluA0856nc6uduTjT3g.png)](https://www.owasp.org/index.php/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities)

**TL;DR:**  With the npm ecosystem it is common to have many dependencies for a project. Dependencies should always be kept in check as new vulnerabilities are found. Use tools like  [npm audit](https://docs.npmjs.com/cli/audit),  [nsp](https://nodesecurity.io/)  or  [snyk](https://snyk.io/)  to track, monitor and patch vulnerable dependencies. Integrate these tools with your CI setup so you catch a vulnerable dependency before it makes it to production.

**Otherwise:**  An attacker could detect your web framework and attack all its known vulnerabilities.

[**Read More:** Dependency security](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/dependencysecurity.md)

### 8. Avoid using the Node.js crypto library for handling passwords, use Bcrypt

[![](https://cdn-images-1.medium.com/max/800/1*T2PGVDn4gYGWPU1sQtMh8Q.png)](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication)

**TL;DR:**  Passwords or secrets (API keys) should be stored using a secure hash + salt function like  `bcrypt`, that should be a preferred choice over its JavaScript implementation due to performance and security reasons.

**Otherwise:**  Passwords or secrets that are persisted without using a secure function are vulnerable to brute forcing and dictionary attacks that will lead to their disclosure eventually.

[**Read More:** Use Bcrypt](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/bcryptpasswords.md)

### 9. Escape HTML, JS and CSS output

[![](https://cdn-images-1.medium.com/max/800/1*IyvIZtDlQzDEZ4d-UndoYw.png)](https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_%28XSS%29)

**TL;DR:**  Untrusted data that is sent down to the browser might get executed instead of just being displayed, this is commonly being referred as a cross-site-scripting (XSS) attack. Mitigate this by using dedicated libraries that explicitly mark the data as pure content that should never get executed (i.e. encoding, escaping)

**Otherwise:**  An attacker might store a malicious JavaScript code in your DB which will then be sent as-is to the poor clients

[**Read More:** Escape output](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/escape-output.md)

### 10. Validate incoming JSON schemas

[![](https://cdn-images-1.medium.com/max/800/1*0-7L-l4-6uHtiLsj84sywg.png)](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization)

**TL;DR:**  Validate the incoming requests’ body payload and ensure it qualifies the expectations, fail fast if it doesn’t. To avoid tedious validation coding within each route you may use lightweight JSON-based validation schemas such as  [jsonschema](https://www.npmjs.com/package/jsonschema)  or  [joi](https://www.npmjs.com/package/joi)

**Otherwise:**  Your generosity and permissive approach greatly increases the attack surface and encourages the attacker to try out many inputs until they find some combination to crash the application

[**Read More:** Validate incoming JSON schemas](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/validation.md)

### 11. Support blacklisting JWT tokens

[![](https://cdn-images-1.medium.com/max/800/1*T2PGVDn4gYGWPU1sQtMh8Q.png)](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication)

**TL;DR:**  When using JWT tokens (for example, with  [Passport.js](https://github.com/jaredhanson/passport)), by default there’s no mechanism to revoke access from issued tokens. Once you discover some malicious user activity, there’s no way to stop them from accessing the system as long as they hold a valid token. Mitigate this by implementing a blacklist of untrusted tokens that are validated on each request.

**Otherwise:**  Expired, or misplaced tokens could be used maliciously by a third party to access an application and impersonate the owner of the token.

[**Read More:**  Blacklisting JWTs](https://github.com/i0natan/nodebestpractices/blob/master/sections/security/expirejwt.md)

### 6.12. Limit the allowed login requests of each user

[![](https://cdn-images-1.medium.com/max/800/1*T2PGVDn4gYGWPU1sQtMh8Q.png)](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication)

**TL;DR:**  A brute force protection middleware such as  [express-brute](https://www.npmjs.com/package/express-brute)  should be used inside an express application to prevent brute force/dictionary attacks on sensitive routes such as  `/admin`  or  `/login`  based on request properties such as the user name, or other identifiers such as body parameters

**Otherwise:**  An attacker can issue unlimited automated password attempts to gain access to privileged accounts on an application

[**Read More:** Login rate limiting](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/login-rate-limit.md)

### 13. Run Node.js as non-root user

[![](https://cdn-images-1.medium.com/max/800/1*oy14hTjHHpmqCrPAHNg0cA.png)](https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control)

**TL;DR:**  There is a common scenario where Node.js runs as a root user with unlimited permissions. For example, this is the default behaviour in Docker containers. It’s recommended to create a non-root user and either bake it into the Docker image (examples given below) or run the process on this users’ behalf by invoking the container with the flag “-u username”

**Otherwise:**  An attacker who manages to run a script on the server gets unlimited power over the local machine (e.g. change iptable and re-route traffic to his server)

[**Read More:** Run Node.js as non-root user](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/non-root-user.md)

### 14. Limit payload size using a reverse-proxy or a middleware

[![](https://cdn-images-1.medium.com/max/800/1*0-7L-l4-6uHtiLsj84sywg.png)](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization)

**TL;DR:**  The bigger the body payload is, the harder your single thread works in processing it. This is an opportunity for attackers to bring servers to their knees without tremendous amount of requests (DOS/DDOS attacks). Mitigate this limiting the body size of incoming requests on the edge (e.g. firewall, ELB) or by configuring  [express body parser](https://github.com/expressjs/body-parser)  to accept only small-size payloads

**Otherwise:**  Your application will have to deal with large requests, unable to process the other important work it has to accomplish, leading to performance implications and vulnerability towards DOS attacks

[**Read More:** Limit payload size](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/requestpayloadsizelimit.md)

[![](https://cdn-images-1.medium.com/max/800/1*itQJfu5RV0MjBonVuUEJjA.png)](https://twitter.com/nodepractices)

Get weekly best practices via our Twitter feed

### 15. Avoid JavaScript eval statements

[![](https://cdn-images-1.medium.com/max/800/1*tPpkf7q604c7YNmcqpiyZw.png)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_%28XXE%29)

**TL;DR:**  `eval`  is evil as it allows executing a custom JavaScript code during run time. This is not just a performance concern but also an important security concern due to malicious JavaScript code that may be sourced from user input. Another language feature that should be avoided is  `new Function`constructor.  `setTimeout`  and  `setInterval`  should never be passed dynamic JavaScript code either.

**Otherwise:**  Malicious JavaScript code finds a way into a text passed into eval or other real-time evaluating JavaScript language functions, and will gain complete access to JavaScript permissions on the page. This vulnerability is often manifested as an XSS attack.

[**Read More:** Avoid JavaScript eval statements](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/avoideval.md)

### 16. Prevent evil RegEx from overloading your single thread execution

[![](https://cdn-images-1.medium.com/max/800/1*egFYL7hd7orI97caxTBKmw.png)](https://www.owasp.org/index.php/Denial_of_Service)

**TL;DR:**  Regular Expressions, while being handy, pose a real threat to JavaScript applications at large, and the Node.js platform in particular. A user input for text to match might require an outstanding amount of CPU cycles to process. RegEx processing might be inefficient to an extent that a single request that validates 10 words can block the entire event loop for 6 seconds and set the CPU on 🔥. For that reason, prefer third-party validation packages like  [validator.js](https://github.com/chriso/validator.js)  instead of writing your own Regex patterns, or make use of  [safe-regex](https://github.com/substack/safe-regex)  to detect vulnerable regex patterns

**Otherwise:**  Poorly written regexes could be susceptible to Regular Expression DoS attacks that will block the event loop completely. For example, the popular  `moment`  package was found vulnerable with malicious RegEx usage in November of 2017

[**Read More:** Prevent malicious RegEx](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/regex.md)

### 17. Avoid module loading using a variable

[![](https://cdn-images-1.medium.com/max/800/1*ubIFsp_ql38gviFcGhBL1Q.png)](https://www.owasp.org/index.php/Top_10-2017_A1-Injection)

**TL;DR:**  Avoid requiring/importing another file with a path that was given as parameter due to the concern that it could have originated from user input. This rule can be extended for accessing files in general (i.e.  `fs.readFile()`) or other sensitive resource access with dynamic variables originating from user input.  [Eslint-plugin-security](https://www.npmjs.com/package/eslint-plugin-security)  linter can catch such patterns and warn early enough

**Otherwise:**  Malicious user input could find its way to a parameter that is used to require tampered files, for example a previously uploaded file on the filesystem, or access already existing system files.

[**Read More:** Safe module loading](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/safemoduleloading.md)

### 18. Run unsafe code in a sandbox

[![](https://cdn-images-1.medium.com/max/800/1*tPpkf7q604c7YNmcqpiyZw.png)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_%28XXE%29)

**TL;DR:**  When tasked to run external code that is given at run-time (e.g. plugin), use any sort of ‘sandbox’ execution environment that isolates and guards the main code against the plugin. This can be achieved using a dedicated process (e.g. cluster.fork()), serverless environment or dedicated npm packages that acting as a sandbox

**Otherwise:**  A plugin can attack through an endless variety of options like infinite loops, memory overloading, and access to sensitive process environment variables

[**Read More:** Run unsafe code in a sandbox](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/sandbox.md)

### 19. Take extra care when working with child processes

[![](https://cdn-images-1.medium.com/max/800/1*ubIFsp_ql38gviFcGhBL1Q.png)](https://www.owasp.org/index.php/Top_10-2017_A1-Injection)

**TL;DR:**  Avoid using child processes when possible and validate and sanitize input to mitigate shell injection attacks if you still have to. Prefer using child_process.execFile which by definition will only execute a single command with a set of attributes and will not allow shell parameter expansion.

**Otherwise:**  Naive use of child processes could result in remote command execution or shell injection attacks due to malicious user input passed to an unsanitized system command.

[Read More: Be cautious when working with child processes](https://github.com/i0natan/nodebestpractices/blob/master/sections/security/childprocesses.md)

### 20. Hide error details from clients

[![](https://cdn-images-1.medium.com/max/800/1*7afKi8CIqClDwZW_UY1xJw.png)](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration)

**TL;DR:**  An integrated express error handler hides the error details by default. However, great are the chances that you implement your own error handling logic with custom Error objects (considered by many as a best practice). If you do so, ensure not to return the entire Error object to the client, which might contain some sensitive application details

**Otherwise:**  Sensitive application details such as server file paths, third party modules in use, and other internal workflows of the application which could be exploited by an attacker, could be leaked from information found in a stack trace

[**Read More:** Hide error details from client](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/hideerrors.md)s

### 21. Configure 2FA for npm or Yarn

[![](https://cdn-images-1.medium.com/max/800/1*7afKi8CIqClDwZW_UY1xJw.png)](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration)

**TL;DR:**  Any step in the development chain should be protected with MFA (multi-factor authentication), npm/Yarn are a sweet opportunity for attackers who can get their hands on some developer’s password. Using developer credentials, attackers can inject malicious code into libraries that are widely installed across projects and services. Maybe even across the web if published in public. Enabling 2-factor-authentication in npm leaves almost zero chances for attackers to alter your package code.

**Otherwise:**  [Have you heard about the eslint developer who’s password was hijacked?](https://medium.com/@oprearocks/eslint-backdoor-what-it-is-and-how-to-fix-the-issue-221f58f1a8c8)

### 22. Modify session middleware settings

[![](https://cdn-images-1.medium.com/max/800/1*7afKi8CIqClDwZW_UY1xJw.png)](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration)

**TL;DR:**  Each web framework and technology has its known weaknesses — telling an attacker which web framework we use is a great help for them. Using the default settings for session middlewares can expose your app to module- and framework-specific hijacking attacks in a similar way to the  `X-Powered-By`  header. Try hiding anything that identifies and reveals your tech stack (E.g. Node.js, express)

**Otherwise:**  Cookies could be sent over insecure connections, and an attacker might use session identification to identify the underlying framework of the web application, as well as module-specific vulnerabilities

[**Read More:** Cookie and session security](https://github.com/i0natan/nodebestpractices/blob/security-best-practices-section/sections/security/sessions.md)

> [⭐](https://github.com/i0natan/nodebestpractices)  **Appreciate the effort? P**[**lease star our project on GitHub**](https://github.com/i0natan/nodebestpractices)

### 23. A list of 40 generic security advice (not specifically Node.js-related)

The following bullets are well-known and important security measures which should be applied in every application. As they are not necessarily related to Node.js and implemented similarly regardless of the application framework — we include them here as an appendix. The items are grouped by their  [OWASP classification](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf). A sample includes the following points:

-   Require MFA/2FA for root account
-   Rotate passwords and access keys frequently, including SSH keys
-   Apply strong password policies, both for ops and in-application user management,  [see OWASP password recommendation](https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Implement_Proper_Password_Strength_Controls%5C)
-   Do not ship or deploy with any default credentials, particularly for admin users
-   Use only standard authentication methods like OAuth, OpenID, etc. — **avoid** basic authentication
-   Auth rate limiting: Disallow more than  _X_  login attempts (including password recovery, etc.) in a period of  _Y_  minutes
-   On login failure, don’t let the user know whether the username or password verification failed, just return a common auth error
-   Consider using a centralized user management system to avoid managing multiple account per employee (e.g. GitHub, AWS, Jenkins, etc) and to benefit from a battle-tested user management system

**The complete list of 40 generic security advice can be found in the official Node.js best practices repository!**

[**Read More: 40 Generic security advice**](https://github.com/i0natan/nodebestpractices/tree/security-best-practices-section#-65-collection-of-common-generic-security-best-practices-15-items)