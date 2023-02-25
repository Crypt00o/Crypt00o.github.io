---
layout: post
title: Directory Traversal
date: 2023-02-24
categories: [Cybersecurity, Web]
---

- In a directory traversal attack, an attacker attempts to access files or directories that are outside of the intended scope of the web application.

## Introduction To Directory Traversal 

![](/media/path-traversal.jpg)

> also known as file path traversal
{: .prompt-tip }


- This is typically done by exploiting vulnerabilities in the application's `handling of user input, such as file paths or URLs`.

- Directory traversal attacks can be used to `steal sensitive data, modify files, or execute malicious code` on the server.

- Directory traversal attacks are often `combined with other attack vectors, such as SQL injection or cross-site scripting (XSS)`, to achieve more comprehensive attacks.

- Directory traversal attacks are especially dangerous because they allow attackers to `access sensitive files or directories` that are not intended to be publicly accessible.

- Preventing directory traversal attacks requires `validating and sanitizing all user input` that could be used to construct file paths or URLs.

- Additionally, it is important to ensure that file system access is restricted to only the files and directories that are necessary for the operation of the web application.

- Other mitigation strategies for directory traversal attacks can include using `chroot jails or sandboxes` to limit the access of the web application to the file system.

- An attacker can use directory traversal to` access files or directories outside of the web application's intended scope`.

- Directory traversal attacks often involve `manipulating file path parameters`, such as using `".." to move up one level` in the `directory hierarchy`.

- By` manipulating file path parameters`, an attacker can potentially `access sensitive files, such as configuration files, user data, or system files`.

- Directory traversal attacks can be performed through various means, such as `URL manipulation, input injection, or HTTP requests`.

- Directory traversal attacks are often used as a stepping stone for further attacks, such as `file inclusion or remote code execution`.


## Examples 

### Retrieve Application Configuration

- For example, an attacker could try to retrieve the web application's configuration file by requesting the following URL:

```
https://exploitable.com/loadVideo?filename=../../../config.php
```

- Assuming that the web application's configuration file is stored in the `/var/www/config.php` file path, the application would read from the following file path:

```
/var/www/images/../../../config.php`
```

- This would cause the application to `read the contents of the "/var/www/config.php"` file, which `could contain sensitive information such as database credentials, API keys`, or other configuration settings.

- Another example of a directory traversal attack would be to retrieve the web application's source code by requesting the following URL:

### Retrieve System Design


```
https://exploitable.com/loadImage?filename=../../../../index.php
```

- Assuming that the web application's source code is stored in the `/var/www/html/index.php` file path, the application would read from the following file path:

```
/var/www/images/../../../../index.php
```

- This would cause the application to read the contents of the `/var/www/html/index.php` file, which `could reveal sensitive information about the application's architecture, design, or vulnerabilities`.

### Retrieve Sensitive Files On System

- another Example shopping application allows users to display images of items for sale by using an HTML tag that references a `server-side script called "loadImage"`. The "loadImage" script takes a `filename parameter`, which specifies the `name of the image file to load`, and `returns the contents of that file as the response`.

- The image files are stored on the server's file system `in the "/var/www/images/"` directory. To load an image file, the "loadImage" script `appends the requested filename to the base directory path and uses a file system API to read the contents of the file`.

- For example, if a user requests an image file with the filename `218.png`, the `loadImage` script would read the file contents from the following path:

```
/var/www/images/218.png
```

However, the shopping application `does not implement any defenses against directory traversal attacks, which allows an attacker to manipulate the "filename" parameter to access arbitrary files on the server's file system`.

In the example provided, the attacker requests an image file with the filename "../../etc/passwd", which causes the "loadImage" script to read the file contents from the following path:

```
/var/www/images/../../../etc/passwd
```

The `../` `sequence in the filename parameter instructs the file system API to step up one level in the directory structure`. By repeating the sequence three times, the attacker can `traverse up to the root directory ("/")`, which allows them to `access sensitive files outside of the web application's directory` structure.


## File Path Traversal With Different OS

In this case, the attacker is able to retrieve the contents of the `"/etc/passwd"` file, which is a standard file on `Unix-based operating systems` that contains information about the system's users.

- On Windows, both `../` and `..\` are `valid directory traversal sequences`, and an equivalent attack to retrieve a standard operating system file would be:

```
https://exploitable.com/loadVideo?filename=..\..\..\windows\win.ini
```
---


## Useful Tricks

### Useing Absolute Path

- One way to bypass these defenses is by `using an absolute path from the filesystem root`. An absolute path specifies the `complete path to a file or directory starting from the root directory`, regardless of the current working directory.

- For example, in a `Unix-based system`, the absolute path to the `/etc/passwd` file is `/etc/passwd`. By using this absolute path instead of a `relative path that includes traversal sequences` , like `/var/www/images/../../../etc/passwd`, an attacker can bypass any defenses implemented by the application to prevent directory traversal attacks.

### Bypassing Common Filters

- In some cases, an application may `attempt to prevent directory traversal attacks by stripping or blocking specific sequences`, such as `../` or `..\`. However, it is possible for an attacker to bypass this protection by using nested traversal sequences.

- For example, an attacker could use a filename like `....//....//file.txt`. The double dot sequences (`..`) are used to navigate up one directory level, and the double forward slashes (`//`) are used to create a nested traversal sequence. When the application attempts to strip the `..` sequences, it will `strip the outermost sequence and leave the inner sequence intact`, resulting in the filename `../../file.txt`.

- Similarly, an attacker could use a filename like `..../..../file.txt`. The double dot sequences (`..`) are again used to navigate up one directory level, but this time a backslash (`/`) and a forward slash (`\`) are used to create a nested traversal sequence. When the application attempts to strip the `..` sequences, it will `strip the outermost sequence and leave the inner sequence intact`, resulting in the filename `../../file.txt`.


### Useing Encodeing Techniques 

- In some contexts, `web servers may strip directory traversal sequences from user input before passing it to the application`. This can be an effective defense against directory traversal attacks, but it is not foolproof. An `attacker may be able to bypass this defense by using various encoding techniques`.

- One such technique is `URL encoding`, where `certain characters are replaced by their corresponding hexadecimal ASCII value preceded by a percent sign ("%")`. For example, the character `.` is encoded as `%2e`. By encoding the `../` sequence as `%2e%2e%2f`, an attacker can `effectively bypass directory traversal protections that are only designed to strip the unencoded sequence`.

- Another technique is `double URL encoding`, where the `../` sequence is encoded twice. For example, the sequence `../` can be encoded as `%252e%252e%252f`. When the first layer of encoding is decoded, the resulting string is `%2e%2e/`, which is then decoded again to produce `../`. This can be effective against protections that are designed to `decode URL-encoded characters, but not double-encoded characters`.

- In addition to these standard encodings, there are various non-standard encodings that may also be effective. For example, an attacker could use the sequence `..%c0%af`, where the `%c0%af` represents the `URL-encoded` form of the Unicode character `U+002F`, which is the forward slash `/` used in directory paths. This can be effective against some protections that are only designed to strip the standard `../` sequence.

- Another example is the sequence `..%ef%bc%8f`, where the `%ef%bc%8f` represents the `URL-encoded` form of the Unicode character `U+FF0F`, which is the full-width slash character used in some Asian languages. This can be effective against some protections that are only designed to strip the standard `../` sequence and its URL-encoded variants.

### Bypassing Sepecific Base Folder Validation 

- In some cases, an application may `require that user-supplied filenames must start with a specific base folder`, such as `/var/www/images`. This can be an effective defense against directory traversal attacks, as it limits the potential scope of the attack. However, it is not foolproof, and attackers may be able to bypass this defense by using suitable traversal sequences.

- One technique is to `include the required base folder followed by traversal sequences that allow the attacker to navigate to the desired file`. For example, an attacker could use a filename like `/var/www/images/../../file.txt`. The `/var/www/images/` prefix `matches the expected base folder`, and the `../` sequences are used to navigate up the directory tree to the parent folder, then down to the desired file. This results in the filename `../../file.txt`, which points to a file outside the expected base folder.

### Bypassing Sepecific File Extension Validation

- If an application `requires that the user-supplied filename must end with an expected file extension`, such as `.png`, then it might be possible to use a `null byte` to effectively `terminate the file path before the required extension`. For example:

```
filename=../../../etc/passwd%00.png
```

---

## TOP 25 Trick


1. Null byte `%00` injection: Some applications use `null bytes as a delimiter for file paths`. Attackers can `inject null bytes into the filename to terminate the path at a specific point and access files outside of the expected directory`. For example, an attacker could use a filename like `/var/www/images/../file%00.txt` to access a file outside the expected directory.

2. Alternate encoding: Attackers can `use alternate encodings to obfuscate traversal sequences and evade defenses that look for specific character patterns`. For example, an attacker could use the sequence `%2e%2e/` instead of `../` or use Unicode encoding to represent the traversal sequence. This can make it harder for defenses to identify and block traversal attempts.

3. Double extension: Attackers can `append a fake extension to a traversal sequence` to `bypass defenses that only look for specific file extensions`. For example, an attacker could use a filename like `/var/www/images/../../file.jpg.php` to bypass defenses that only allow image files.

4. Case sensitivity: File path traversal defenses that are not case-sensitive may be vulnerable to attacks that use different case combinations for traversal sequences. For example, an attacker could use the sequence `/VAR/www/images/../../file.txt` instead of `/var/www/images/../../file.txt` to bypass defenses that only check for lowercase traversal sequences.

5. URL-encoded null byte: Similar to null byte injection, an attacker can use `URL-encoded null bytes (%2500) to terminate the file path and access files` outside the expected directory.


6. Using symbolic links: Attackers can use `symbolic links to create a fake path` that appears to be within the expected directory, but `actually points to a file outside of the directory`. For example, an attacker could create a `symbolic link` from `/var/www/images/../../tmp/mylink` to `/etc/passwd`, then use the filename `/var/www/images/../../tmp/mylink/file.txt` to access the `/etc/passwd` file.

7. Using null bytes in alternate encodings: Attackers can use `null bytes in alternate encodings to bypass defenses that remove or block null bytes`. For example, an attacker could use a filename like `/var/www/images/%252e%252e%00file.txt` to access a file outside the expected directory.

8. URL-encoded slash: Attackers can use `URL-encoded slashes` `%2f` to bypass defenses that `only check for directory traversal sequences`. For example, an attacker could use a filename like `/var/www/images%2f../file.txt` to bypass defenses that only look for `../` sequences.

9. Double URL encoding: Attackers can use `double URL encoding to bypass defenses` that only decode URL-encoded characters once. For example, an attacker could use the sequence `%252e%252e/` instead of `%2e%2e/` to evade defenses that only decode the first layer of URL encoding.

10. Overlong UTF-8 encoding: Attackers can use `overlong UTF-8 encoding to obfuscate traversal sequences` and bypass defenses that `only look for specific encodings`. For example, an attacker could use a filename like "`var/www/images/%c0%ae%2f/file.txt` to represent the sequence `../` in overlong UTF-8 encoding.

11. Using backslashes: In `Windows environments`, attackers can `use backslashes instead of forward slashes` to represent directory traversal sequences. For example, an attacker could use a filename like `C:\Windows\System32..\file.txt` to access a file outside the expected directory.

12. Using environment variables: Attackers can use `environment variables` to bypass defenses that `rely on fixed file paths`. For example, an attacker could use a filename like `%USERPROFILE%..\file.txt` to access a file outside the user's home directory.

13. Using relative paths: Attackers can use `relative paths to bypass defenses` that only check for `absolute paths`. For example, an attacker could use a filename like `../../file.txt` to access a file outside the expected directory.

14. Using null bytes to hide file extensions: Attackers can `use null bytes to hide the actual file extension and bypass defenses that only check for specific file extensions`. For example, an attacker could use a filename like `file.php%00.jpg` to evade defenses that only allow image files.

15. Using Unicode encoding: Attackers can `use Unicode encoding to obfuscate traversal sequences and bypass defenses` that only look for specific encodings. For example, an attacker could use a filename like `/var/www/images/%u002e%u002e/file.txt` to represent the sequence `../` in Unicode encoding.

16. Using path truncation: Attackers can `use path truncation` to bypass defenses that rely on `fixed file path lengths`. For example, an attacker could use a filename like `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/file.txt` to `truncate the path and access a file` outside the expected directory.

17. Using remote file inclusion: Attackers can use `remote file inclusion to include external files` and bypass defenses that only check for local file paths. For example, an attacker could use a `PHP script to include a remote file with a malicious payload`.

18. Using file upload vulnerabilities: Attackers can `use file upload vulnerabilities to upload malicious files` and bypass defenses that `only check for specific file paths`. For example, an attacker could use a file upload vulnerability to `upload a file with a malicious payload to the server`.


19. Using blind path traversal: Attackers can `use blind path traversal to guess file paths` and bypass defenses that `only check for specific file paths`. For example, an attacker could `use a brute-force attack to guess the location of a sensitive file based on its filename`.

20. Using directory listing vulnerabilities: Attackers can `use directory listing vulnerabilities to view sensitive files` and bypass defenses that `only check for specific file paths`. For example, an attacker could `use a directory listing vulnerability to view a list of files in a directory and then access sensitive files by guessing their names`.


21. Using hidden inputs: Attackers can `use hidden inputs to pass file paths` and bypass defenses that `only check for user-supplied inputs`. For example, an attacker could `use a hidden input to pass a file path with a malicious payload to the server`.

22. Using path normalization: Attackers can `use path normalization` to bypass defenses that `only check for specific file paths`. For example, an attacker could use a path like `/../etc/passwd` to evade defenses that only allow files in the `/var/www` directory.

23. Using parameter tampering: Attackers can `use parameter tampering to modify file paths` and bypass defenses that` only check for specific file paths`. For example, an attacker could `modify a parameter like "filename=example.jpg" to "filename=../../etc/passwd"` to access sensitive files.

24. Using data leakage vulnerabilities: Attackers can `use data leakage vulnerabilities to view sensitive files` and bypass defenses that `only check for specific file paths`. For example, an attacker could` use a data leakage vulnerability to view the contents of a file and then access sensitive files by guessing their names`.

25. Using user-level permissions: Attackers can `use user-level permissions to bypass defenses that only check for specific file paths`. For example, an attacker could `use a user-level permission to access a sensitive file that is not accessible to the current user`.


> Directory Traversal vulnerabilities can often be combined with other vulnerabilities to achieve even greater impact. For example, an attacker might use a Directory Traversal vulnerability in combination with a `Remote File Inclusion` (RFI) vulnerability to execute arbitrary code on a server , also `SQL Injection` or `Cross-Site Scripting` (XSS), to gain additional access or control over a system..
{: .prompt-tip }


---


