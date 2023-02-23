---
layout: post
title: Broken Access Control
categories: [Cybersecurity, OWASP]
---


- `Access control, also known as authorization`, is a security mechanism that `ensures only authorized individuals or entities can access specific resources or perform particular actions`. Access control systems are used to enforce security policies and protect sensitive data by limiting access to it.

- In the context of web applications, access control is based on `authentication and session management`. Authentication identifies the user and verifies their identity. It `ensures that only legitimate users can access the application, by requiring a password, a PIN, or some other form of identification`. Session management keeps track of which user is currently logged in and the actions they perform.

- Access control determines whether the user has the necessary permissions to perform a particular action or access a resource. This can be controlled at different levels such as at the application, file, or database level. Access control can be divided into three categories: 

	  1. vertical 
	  2. horizontal 
	  3. context-dependent.

---

# Vertical Access Control  

- Vertical access controls are a security mechanism that restricts access to sensitive functions or resources based on the user's role or authority level within an organization. This type of access control is more fine-grained than other types of access controls and enforces business policies such as separation of duties and least privilege. By `limiting access to sensitive functions, vertical access controls help prevent unauthorized access and reduce the risk of security breaches`. Vertical access controls can be used in a variety of systems, including enterprise systems, financial institutions, and government organizations. They are an essential component of an effective access control system, helping to `ensure that users only have access to the functions and resources necessary to perform their job or task`. Effective implementation of vertical access controls requires careful consideration of user roles and responsibilities and ongoing monitoring to `ensure that users are only granted the appropriate level of access`. Failure to properly implement vertical access controls can lead to serious security vulnerabilities and breaches.

---

## Horizontal Access Control

- Horizontal access controls are a security mechanism used to restrict access to specific resources to authorized users. This type of access control is based on the resources being accessed, rather than the user's role or authority level. For example, a `user may be authorized to access their own bank account but not the accounts of others`. This approach `ensures that users only have access to the resources necessary to perform their job or task, reducing the risk of unauthorized access or data breaches`. Horizontal access controls can be implemented in various ways, such as through access control lists `ACLs, permissions, or other security policies`. Effective implementation of horizontal access controls requires ongoing monitoring and maintenance to ensure that users only have access to the appropriate resources. Failure to properly implement horizontal access controls can lead to serious security vulnerabilities and breaches, highlighting the importance of this security mechanism.


---

## Context-Dependant Access Control

- Context-dependent access controls are a security mechanism that restricts access to resources and functionality based on the context or state of the application or the user's interaction with it. This type of access control is designed to `prevent users from performing actions in the wrong order, or accessing resources or functionality in inappropriate contexts`. For example, a `user may not be able to modify their shopping cart after they have completed a purchase on a retail website`. Context-dependent access controls help prevent security breaches and ensure that users are only able to access the appropriate resources and functionality. These controls can be implemented in various ways, such as through `user session data or application state data`, and require careful design and planning to ensure effective operation. Failure to properly implement context-dependent access controls can lead to serious security vulnerabilities and breaches, highlighting the importance of this security mechanism.

---


## 1. Vertical Privilege Escalation

- Vertical privilege escalation is a type of security vulnerability `where a user gains access to functionality or resources that they are not authorized to access`. This typically involves a non-administrative user `gaining access to admin-level privileges, such as the ability to delete user accounts`. Vertical privilege escalation can occur through various means, such as exploiting a software vulnerability or by manipulating user inputs. It is a serious security issue that can lead to unauthorized access to sensitive data or system compromise. Effective access control and security mechanisms are necessary to prevent vertical privilege escalation.

### 1. Unprotected functionality 

- Unprotected functionality is a type of security vulnerability that ` allows unauthorized access to sensitive functionality without proper access controls`. It arises when an application `fails to enforce protection over sensitive functions, such as administrative functions `, and can occur due to poor design or implementation. Attackers can exploit unprotected functionality by directly ` accessing sensitive URLs `, allowing them to gain unauthorized access to sensitive data or resources. It is important to implement proper access controls and security mechanisms to protect against unprotected functionality vulnerabilities.

```
https://exploitable.com/admin
```
- `Security by obscurity` is a technique that involves `hiding sensitive functionality behind a less predictable URL`. However, this method does not provide effective access control as users might still discover the `obfuscated URL` in various ways. One way in which the URL might be `leaked is through application scripts` that construct the user interface based on the user's role. These scripts might add links to sensitive functionality in the UI, but the script containing the URL is visible to all users, regardless of their role. As a result, an attacker might still be able to discover the URL and gain access to sensitive functionality.

example :

```js
<script>
var isAdmin = false;
if (isAdmin) {
	...
	var adminPanelTag = document.createElement('a');
	adminPanelTag.setAttribute('https://exploitable.com/administrator-panel-main'); // here is the url for admin panel 
	adminPanelTag.innerText = 'Admin panel';
	...
}
</script>
```
---

### 2. Parameter-based access control methods

- Some applications determine the user's access rights or role at login, and then `store this information in a user-controllable location, such as a hidden field, cookie, or preset query string parameter`. The application makes subsequent access control decisions based on the submitted value. For example:

```
https://exploitable.com/login/home.php?admin=true
https://exploitable.com/login/home.php?id=0&admin=true
```
this is insecure because we can gain access simplify by modify `hidden field, cookie, or preset query string parameter`

---

### 3. Platform misconfiguration 
- Platform misconfiguration can occur ` when applications use front-end controls to restrict access based on URL, but the application in backend-levels allows the URL to be overridden via a request header`. For example, some frameworks support non-standard HTTP headers like `X-Original-URL` and `X-Rewrite-URL` that can be used to ` override the original request URL, leading to potential access control bypasses`. This can result in users being able to access functionality that they are not authorized to use, leading to security vulnerabilities in the application.

- In some cases, an attacker can bypass access controls by `using a different HTTP method to make a request to a restricted URL`. For example, if a web application uses rigorous front-end controls to restrict access to an action using the `POST` method on the URL `/admin/deleteUser`, but is tolerant of the `GET` method for the same action, an attacker can use the `GET` method to perform the action and bypass the access controls implemented at the platform layer. This is an example of an alternative attack on access controls.

---

## 2. Horizontal privilege escalation

- Horizontal privilege escalation arises when a `user is able to gain access to resources belonging to another user, instead of their own resources of that type`. For example, if an `employee should only be able to access their own employment and payroll records, but can in fact also access the records of other employees`, then this is horizontal privilege escalation.

- Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation. For example, a user might ordinarily access their own account page using a URL like the following:
```
https://exploitable.com/profile?id=123
```

- Now, if an attacker modifies the `id` parameter value to that of another user, then the attacker might gain access to another user's account page, with associated data and functions.

- Some applications use `globally unique identifiers (GUIDs) instead of predictable values for identifying users`. An attacker may not be able to predict the GUIDs, but they could be disclosed in other parts of the application where users are referenced, such as `user reviews or messages. This could allow an attacker to perform vertical privilege escalation by manipulating the GUID parameter`.

- In some cases, `when a user is not permitted to access a resource, the application may redirect them to the login page. However, the response containing the redirect could still include sensitive data belonging to the user`. This could be intercepted by an attacker, allowing them to `access sensitive information without proper authorization`. Therefore, returning a redirect to the login page alone does not always guarantee protection against such attacks.

### Transform Horizontal to Vertical Privilege Escalation 

- `Horizontal privilege escalation attacks can often lead to vertical privilege escalation` by compromising a more privileged user. For instance, compromising an `administrative user account can give attackers administrative access and allow them to perform vertical privilege escalation. Using parameter tampering, attackers might be able to gain access to an administrative account page, which can disclose passwords or provide direct access to privileged functionality`. Therefore, it is crucial to identify and fix horizontal privilege escalation vulnerabilities to prevent vertical privilege escalation.

### Insecure direct object references (IDOR)

- Insecure direct object references (IDOR) refer to a vulnerability where an application uses `user-supplied input to access objects directly, and an attacker can modify the input to gain unauthorized access`. This type of vulnerability allows attackers to access `sensitive information or functionality without proper authorization`. IDORs can arise from implementation mistakes, such as `failing to check user authorization or not validating input`. They were popularized by their appearance on the OWASP Top Ten in 2007, and continue to be a common vulnerability in web applications. To prevent IDOR vulnerabilities, `developers should use access controls and input validation to ensure that users can only access authorized resources`. Additionally, they should avoid exposing object references in URLs or other user-supplied input. Regular security testing and vulnerability assessments can also help identify and mitigate IDOR vulnerabilities.




