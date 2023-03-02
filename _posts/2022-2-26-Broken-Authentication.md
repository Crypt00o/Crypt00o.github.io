---
layout: post
title: Broken Authentication
date: 2023-02-26
categories: [Cybersecurity, Web]
cover_image: /media/broken_auth.png
og_image: /media/broken_auth.png
---

## Introduction 

![](/media/broken_auth.png)

- Authentication vulnerabilities are security weaknesses in the `process of verifying user identity to access websites or applications`. They are `critical` because they can `provide attackers with direct access to sensitive data and functions`, as well as expose additional attack surface. Identifying and exploiting authentication vulnerabilities is a `fundamental skill in cybersecurity`. Common authentication mechanisms, such as `passwords, biometrics, and multi-factor authentication`, have inherent vulnerabilities and can be compromised if implemented improperly. `Weak passwords, lack of complexity requirements, and improper storage of passwords` can make password-based authentication vulnerable. Biometric authentication can be `vulnerable to spoofing attacks`, while multi-factor authentication can be `vulnerable to social engineering attacks`. To ensure robust authentication mechanisms, developers should follow best practices and regularly assess vulnerabilities.



## Authentication Factors

- Authentication factors are used to `verify a user's identity` when accessing a website or application. They are categorized into something you know, something you have, and something you are or do.
1. `Knowledge factors` include `passwords and security questions`.
2. `Possession factors` include `physical objects` such as `mobile phones or security tokens`. 
3. `Inherence factors` include `biometric traits` like `fingerprints`, `facial recognition`, and `patterns of behavior`. 

- Authentication mechanisms that `use multiple factors` are considered `more secure` than those that use only one.

## Why Broken Authentication Occur

- Authentication `mechanisms can be weak` due to inadequate protection against `brute-force attacks, logic flaws, or poor coding in implementation`. 
1. Flaws in the authentication logic can allow attackers to `bypass the mechanism entirely`, leading to a `broken authentication` scenario. 
2. Logic flaws may cause `unexpected website behavior`, which could lead to security vulnerabilities. However, `flawed authentication logic poses a higher risk` to security, as it `undermines the primary safeguard for protecting sensitive data and functionality`. 

> Therefore, identifying and addressing broken authentication vulnerabilities is crucial to maintaining robust security.




## Consequences of Broken Authentication 

- Authentication vulnerabilities can have a significant impact on the security of a website or application. If an attacker is `able to bypass or brute-force their way into another user's account`, they can `gain access to all the data and functionality associated with that account`. This can be particularly dangerous if the compromised account belongs to a `high-privileged user`, such as a `system administrator`, as the attacker could potentially `take control of the entire application and even gain access to internal infrastructure`.

Even a compromised `low-privileged account` can still provide valuable information to the attacker, such as `commercially sensitive business data`. Furthermore, the attacker could use this account to `access additional pages and features of the application`, which could `open up further vulnerabilities`. It is also important to note that `certain high-severity attacks may only be possible from internal pages`, rather than `publicly accessible ones`, making it even `more critical to secure all aspects of the authentication process`.

# Authentication Vulnerabilities

## Vulnerabilities in password-based login

- Password-based login is vulnerable to attacks such as `brute-force` and `dictionary attacks`, where attackers can `guess or try passwords until they succeed`. `Weak passwords`, `password reuse`, and `poor password policies` can also make password-based login vulnerable. Additionally, password-based login can be susceptible to `phishing attacks`, where attackers `trick users into giving away their passwords`. Finally, password-based login may be vulnerable if passwords are stored improperly or transmitted insecurely.

- Websites using password-based login require users to have a `unique username and secret password to authenticate` themselves. If an attacker is able to `obtain or guess these credentials`, they can compromise the security of the website. This makes it crucial to ensure that `passwords are strong, unique, and stored securely`. Additionally, implementing measures such as `multi-factor authentication and rate-limiting login` attempts can help to mitigate the risk of brute-force attacks.

### Brute-force Attacks | Dictionary Attacks

- A brute-force attack is a method used by attackers to gain access to a system or account by `guessing usernames and passwords through automated trial and error`. or By `using wordlists of common passwords and usernames (dictionary attack`), attackers can automate this process and make a `large number of login attempts` at high speed. These attacks can be even `more efficient if attackers use publicly available information or basic logic to make more educated guesses`. Websites that rely solely on password-based authentication can be particularly vulnerable to `brute-force` attacks if they do not have adequate protection mechanisms in place to detect and prevent such attacks.


#### Brute-forcing Usernames

- Attackers can `use publicly available information or basic logic to make educated guesses` when performing a brute-force attack. 
- Usernames are often easy to guess if they follow a `predictable pattern or are publicly disclosed`. Common `username patterns, such as email addresses`, can be easily guessed and targeted by attackers. `Predictable usernames`, like `admin` or `administrator` may also be targeted.

- During website `auditing`, it's important to check for any potential `username disclosures`. This can include `accessing user profiles without logging in`, `checking HTTP responses for email addresses`  responses contain `emails addresses of high-privileged users like administrators and IT support !`. , or `looking for any other publicly accessible information that could reveal usernames`. By `discovering potential usernames`, security measures such as `password complexity requirements` or `account lockouts` can be implemented to reduce the risk of brute-force attacks.



#### Brute-forcing Passwords 

- Brute-forcing passwords involves  using trial and error to guess the correct password by trying various combinations of characters until the correct password is found. `Password policies enforced by websites often require users to create strong, complex passwords to make them harder to guess`. These policies usually include `requiring a minimum number of characters, a mix of uppercase and lowercase letters, and at least one special character`.

- However, even with these `strong password policies`, users often create passwords that are `still vulnerable to brute-force attacks`. This is `because users tend to create passwords that are easy to remember rather than random and complex`. As a result, attackers can `use common patterns and predictable behaviors to make educated guesses about the password`. For example, users may simply add a number or special character to their preferred password, or they may slightly modify their password when required to change it.

- This knowledge of `likely credentials and predictable patterns` `allows attackers to conduct more sophisticated brute-force attacks that can be highly effective in cracking passwords`. Therefore, it is important for websites to `implement additional security measures to protect against brute-force attacks`, such as `account lockout policies`, `multi-factor authentication`, and `rate limiting`.

#### User Enumeration

- Username enumeration is a technique used by attackers to `identify valid usernames on a website`. It involves `submitting multiple requests to a login or registration page with different username`s, and observing any changes in the website's behavior that could indicate whether the username is valid or not.

- There are three main indicators that attackers look for during username enumeration: status codes, error messages, and response times.

1. `Status codes` are returned by the web server in response to a request, and they indicate whether the request was successful or not. During a `brute-force attack, most of the guesses will be incorrect and will result in the same status code being returned`. However, if a `guess returns a different status code, it suggests that the username was correct`. Websites should always return the same status code regardless of the outcome to prevent username enumeration, but this is not always the case.

2. `Error messages` are also useful for `identifying valid usernames`. If a website `returns different error messages depending on whether the username or password was incorrect`, an attacker can `use this information to narrow down the list of valid usernames`. Websites should use identical, generic error messages in both cases to prevent username enumeration, but sometimes small typing errors can cause the messages to be distinct.

3. `Response times` can also be used to `identify valid usernames`. If most requests are `handled with a similar response time, any that deviate from this suggest that something different is happening behind the scenes`. For example, a `website might only check whether the password is correct if the username is valid`. This extra step `might cause a slight increase in the response time`, which an attacker can use to identify valid usernames.

- In summary, username enumeration is a technique that attackers use to identify valid usernames on a website. They do this by `submitting multiple requests with different usernames and observing any changes in the website's behavior that could indicate whether the username is valid or not, such as status codes, error messages, and response times`.


> we can use `X-Forwarded-For` and `Forwarded`  headers to spoof  requests if server behind a  proxy or loadblancer .
{: .prompt-tip }

> Spoofing `X-Forwarded-For` and Forwarded headers involves manipulating or falsifying the values of these headers in an attempt to mislead or deceive a server or application that relies on this information. Both headers are used to convey information about the client's IP address and the origin of the request.


- `X-Forwarded-For` header is a `non-standard header` that is often `used by proxies, load balancers, and other intermediate servers to identify the original client IP address in the request`. When a server receives a request, it typically sees the IP address of the last proxy or load balancer in the chain. The `X-Forwarded-For` header is used to `pass the original client IP address to the server`. format : `X-Forwarded-For: client, proxy1, proxy2`

example : 

```
X-Forwarded-For: 203.0.113.195, 70.41.3.18, 150.172.238.178
X-Forwarded-For: 203.0.113.195
X-Forwarded-For: 2001:db8:85a3:8d3:1319:8a2e:370:7348
```



- `Forwarded` header is a newer `standard` that replaces X-Forwarded-For and provides a more standardized way of conveying the client IP address and other information about the request origin. The Forwarded header `includes information such as the client IP address, the protocol used, and the port number`.


exmaple :

```
Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
```

- Spoofing these headers can be done by a malicious user or attacker who wants to hide their true identity or location. By manipulating the values of these headers, an attacker can make it appear as if the request is coming from a different client or location. This can be used to bypass security measures, such as `IP-based access controls` or `rate limiting`, or to `launch attacks that rely on the target server or application trusting the information provided by these headers`.

- Let's say that there is a server with IP address `10.0.0.1` that is `protected by a firewall that only allows traffic from IP addresses in the range 10.0.0.0/24`. An attacker with IP address `192.168.1.100` wants to bypass the firewall and access the server.

> The attacker can send a request to the server with a `spoofed X-Forwarded-For and Forwarded header`,
{: .prompt-tip }


like this:

```
GET /secret-page HTTP/1.1
Host: exploitable.com
X-Forwarded-For: 10.0.0.2, 192.168.1.100
Forwarded: for=10.0.0.2;proto=http
```

- In this example, the attacker has spoofed the `X-Forwarded-For` header to make it look like the request is coming from IP address `10.0.0.2` (which is allowed by the firewall) and also added their own IP address `192.168.1.100` to make it appear as if the `request is coming from a trusted source`. The attacker has also spoofed the Forwarded header to include the same information.

- If the server trusts the values of these headers and allows access based on the IP address in the X-Forwarded-For header, it may `grant the attacker access to the protected resource, even though the request actually originated from an unauthorized IP address`.

 - In a brute-force attack, the attacker attempts to guess a user's login credentials by trying multiple combinations of usernames and passwords until they find the correct one. If a server has `rate-limiting or other security measures in place to block repeated login attempts from a single IP address`, an attacker may try to `bypass these measures by spoofing the X-Forwarded-For and Forwarded headers`.

- For example, the attacker may use a script or tool that sends login requests to the server with `different usernames and passwords`, each time `changing the IP address in the X-Forwarded-For and Forwarded header`s to make it appear as if the requests are coming from `different IP addresses`. By doing this, the attacker can `evade rate-limiting and other IP-based security measures`, and increase their chances of successfully guessing the correct login credentials.

##### User Enumeration via Acount Locking

- When a `website detects multiple failed login attempts from a single user or IP address`, it `may implement security measures to prevent further attempts`, such as `locking the user's account` or `adding a delay between login attempts`. These measures can help prevent brute-force attacks `by limiting the number of attempts an attacker can make within a given time period`.

- However, the way in which the server responds to these security measures can also provide valuable information to an attacker. For example, if an `attacker tries to log in to an account with a valid username and a series of incorrect password`s, the server may `eventually lock the account after a certain number of failed attempts`. If the server `responds to a locked account with a specific error message or status code`, such as `account locked` or `HTTP 403 Forbidden`, the attacker can use this information to `enumerate valid usernames` by `sending login requests with different usernames and checking the server's response`.

- By doing this, the attacker can `identify which usernames are valid and which ones are not`, without even needing to guess the password. This technique is known as username enumeration and can be used to collect a list of valid usernames that can then be targeted in a more `focused brute-force attack`.

- Account locking also fails to protect against `credential stuffing attacks`. This involves `using a massive dictionary` of `username:password pairs`, composed of `genuine login credentials stolen in data breaches`. Credential stuffing relies on the fact that `many people reuse the same username and password on multiple websites `and, therefore, there is a chance that some of the compromised credentials in the dictionary are also valid on the target website.

##### Buteforce Over User-RateLimit 

- User rate limiting is a common defense against brute-force attacks, but as with any security measure, it is not foolproof. One way an attacker can potentially bypass user rate limiting is by using a technique called `password spraying`

- In a password spraying attack, the attacker `tries a small number of commonly used passwords (such as "password" or "123456") across a large number of usernames or vice versa`. By doing this, the attacker can `avoid triggering the rate limiting mechanism, since they are only making one request for each username, even though they are trying multiple passwords`.

- For example, let's say a website has a `rate limit of 10 login attempts per minute per IP address`. An attacker who wants to brute-force a particular account could `use password spraying by trying list of  passwords  for a list of  different usernames`. in only one request 


##### HTTP Basic-Authenctication

- HTTP basic authentication is a simple method of authentication used by some websites. However, it has a number of weaknesses that make it insecure.

- One major issue with HTTP basic authentication is that it `involves sending the user's login credentials with every request`. This means that if an `attacker is able to intercept the traffic between the client and server` (such as `through a man-in-the-middle attack`), they can easily `capture the user's credentials`.

- Another weakness of HTTP basic authentication is that it typically `doesn't support brute-force protection`. This means that an attacker can `repeatedly send login attempts with different username and password combinations until they find the correct credentials`. As the `token used in HTTP basic authentication consists of static values`, it can be easily brute-forced.

- HTTP basic authentication is also `vulnerable to session-related attacks`, such as `CSRF` (cross-site request forgery). CSRF attacks `involve tricking a user into making a request that they didn't intend to make`, which can `allow an attacker to perform actions on their behalf`.



Even if a vulnerability in HTTP basic authentication only grants an attacker access to a seemingly uninteresting page, it can still provide an entry point for further attacks. Additionally, the credentials that are exposed through the vulnerability could be reused by the attacker in other contexts to gain access to more sensitive information or resources.

In summary, HTTP basic authentication is generally not considered a secure authentication method due to its weaknesses in protecting against interception, brute-force attacks, and session-related exploits. Other more secure authentication methods, such as token-based authentication or multi-factor authentication, should be used instead.

### Two Factor Authentication Vulnerabilities


- Authentication is the process of confirming the identity of a user. <u> Single-factor authentication</u> `relies on a single form of identification, such as a password, to authenticate a user's identity`. However, this method `can be compromised if the password is weak or if it falls into the wrong hands`.

- To enhance security, some websites `use multi-factor authentication`, which `requires users to provide more than one form of identification to prove their identity`. The two most common forms of multi-factor authentication are `something you know and something you have`.

- Something you know `refers to a piece of information that only the user should know, such as a password or PIN`. Something you have `refers to a physical object that only the user should have, such as a smartphone or a security token`. By requiring both forms of identification, multi-factor authentication `makes it more difficult for attackers to compromise a user's account`.

- While verifying biometric factors, such as fingerprint or facial recognition, may be impractical for most websites, two-factor authentication is becoming increasingly common. This method requires users to `enter both a password and a temporary verification code that is sent to an out-of-band physical device in their possession`, such as a smartphone. By requiring both something the user knows (password) and something the user has (smartphone), two-factor authentication provides an extra layer of security.

- It is important to note that the `full benefits of multi-factor authentication are only achieved when verifying multiple different factors`. Verifying the `same factor, such as a password, in two different ways is not considered true multi-factor authentication`. For example, `email-based two-factor authentication may require a user to enter a password and a verification code sent to their email account`. However, since `both factors rely on the user's knowledge, this is not true multi-factor authentication`.




#### 2 FA Authentication Tokens

- Two-factor authentication tokens are `physical devices or apps that generate a temporary verification code for the user to enter during the authentication process`. These devices are designed to provide an `additional layer of security beyond a password, by requiring something the user has (the token) in addition to something the user knows (the password)`.

- Dedicated two-factor authentication devices, such as the `RSA token or keypad device`, generate a `unique verification code that changes every 30-60 seconds`. These devices are designed to be `highly secure and tamper-resistant`, making them difficult for attackers to compromise. Some devices also require the user to enter a PIN or biometric information, such as a fingerprint, to access the verification code.

- Mobile apps, such as `Google Authenticator`, can also be used as `two-factor authentication tokens`. These apps `generate a verification code that changes every 30-60 seconds`, and the user must enter this code in addition to their password to access their account. These apps are often more convenient for users than dedicated devices since they can be easily installed on a smartphone.

- However, some websites send verification codes to a user's mobile phone as a text message, which is `considered less secure than using a dedicated token`. `SMS messages can potentially be intercepted`, and attackers can also `perform SIM swapping attacks to intercept the verification code`. For this reason, it is generally recommended to use a dedicated two-factor authentication token or app whenever possible to ensure the highest level of security.

#### Bypassing 2FA Common Logic Flaws

- Two-factor authentication is `not foolproof`, and there have been instances where `its implementation has been flawed, allowing attackers to bypass the second authentication step entirely`.

- One common flaw is <u>when the user is first prompted to enter a password and then directed to a separate page to enter the verification code. If the website does not check if the verification code has been entered before loading the "logged-in only" page</u>, an `attacker can potentially skip the second authentication step by accessing the "logged-in only" page directly after completing the password step`.

- Another flaw is <u>when the website allows users to select `remember this device` after entering the verification code once</u>. This means that the user `will not be required to enter the verification code again when accessing the website from the same device in the future`. `If an attacker gains access to the user's device`, they may be `able to bypass the second authentication step` altogether.

- Additionally, some websites `may allow users to bypass two-factor authentication entirely by providing an option to disable it in the account settings`. If an attacker gains access to the user's account, they can `simply disable two-factor authentication and gain unrestricted access`.

- Another flaw is leading to `not-completed verification of the user's identity`. This vulnerability occurs `after the user has successfully completed the initial login step`.

- for example , let's say that a user logs in by sending a `POST` request to the `login page` of a website:

http-request:

```
POST /login HTTP/1.1
Host: exploitable.com
...
username=johnsmith&password=abcd1234
```

- Upon successful authentication, the `website assigns a cookie to the user that is linked to their account`. The user is then taken to the `second step` of the login process:

http-response:
```
HTTP/1.1 200 OK
Set-Cookie: account=Crypt00o
```

http-request:

```
GET /second-login-step HTTP/1.1
Cookie: account=Crypt00o
```

The user is required to enter a verification code in the second step of the login process. The `website uses the cookie to determine which account the user is attempting to access`:

http-request:

```
POST /second-login-step HTTP/1.1
Host: exploitable.com
Cookie: account=Crypt00o
...
verification-code=987654
```

However, a malicious `attacker can exploit this vulnerability by logging in with their own credentials and then changing the value of the account cookie to an arbitrary username when submitting the verification code`:

http-request:

```
POST /second-login-step HTTP/1.1
Host: exploitable.com
Cookie: account=someone
...
verification-code=987654
```

#### Buteforce to Bypass 2FA

- If the attacker is `able to brute-force the verification code`, they can `gain access to other users' accounts without knowing their passwords`. This flaw in the two-factor authentication process poses a `significant security risk`.


- Because many 2FA verification codes are `simple numeric codes`, they are `vulnerable to brute-force attacks`. To prevent this, websites should implement measures such as `rate limiting, where the website limits the number of login attempts allowed per unit of time, or locking out the account after a certain number of failed attempts`.

- However, some experienced attackers can `bypass these protections by using multiple IP addresses or by using advanced techniques such as distributed computing and with automation useing spefic scripts or macros ` . In these cases, it becomes important for websites to implement more advanced protection mechanisms such as `device fingerprinting or behavior analysis`, which can detect unusual patterns of login attempts and block them before they succeed.

