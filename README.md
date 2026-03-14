# Cyber Security Course Project

This project was done for the University of Helsinki Cyber Security course. It demonstrates 5 different security flaws from the OWASP 2021 list.

## Instructions to get the app running

After cloning the repository, create and activate a virtual environment
```
python3 -m venv venv
```
```
source venv/bin/activate
```
Install dependencies
```
pip install -r requirements.txt
```
Run migrations
```
python manage.py migrate
```
Create a superuser for the admin panel (from there you can manage polls)
```
python manage.py createsuperuser
```
Start the development server
```
python manage.py runserver
```

## Report

#### FLAW 1:
A02:2021 Cryptographic Failures: password is stored in plaintext without hashing
Exact source link:
https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L62

Description:

When a user registers, their password is stored as plaintext by directly assigning it to user.password. The password is therefore visible in the database without any hashing or protection. This means that if an attacker gains access to the database, they would immediately have all the passwords of all users. Many people reuse the same password across different services, so this could allow the attacker to access the users’ accounts on other platforms too. Raw passwords should never be stored, and instead, a cryptographic hashing algorithm should be used before storing the password. When passwords are properly hashed, an attacker would only see hashed values for passwords even if they did get access to the database.

How to fix:

This flaw can be fixed using Django’s built-in password hashing. Uncomment line 65 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L65) and comment out line 63 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L63). Also update the login view to use user.check_password(password) instead of the plaintext comparison by uncommenting lines 98-101. This ensures that passwords are never stored in plaintext, and significantly improves the security of the application.

#### FLAW 2:
A07:2021 Identification and Authentication Failures: no rate limiting, attacker can brute-force passwords
Exact source link:
https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L82

Description:

The login view has no rate limiting, which allows attackers to brute-force passwords without any delay or attempt tracking. An attacker can repeatedly attempt to guess users’ passwords without being locked out. If the attacker uses an automated script, the password could be cracked quickly, especially if the user uses a weak password. This can be particularly harmful if the user has elevated privileges on their account, such as administrator access. In that case, the attacker would have control over the entire application. To prevent this type of attack, the number of failed login attempts should always be limited within a certain time period.

How to fix:

Use Django’s cache to track attempts per IP/username, and block after 5 failures. Uncomment the rate limiting code on lines 84-89 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L84), line 96 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L96) which resets on success, and line 106 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L106) which increments when a login attempt fails. By limiting login attempts to 5 failures, brute-force attacks are significantly slower and more difficult to execute.

#### FLAW 3:
A01:2021 Broken Access Control: any logged-in user can view any question by ID
Exact source link:
https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L20

Description:

The question detail view fetches any question by ID, without checking who has permission to view it (should be currently logged-in user). Because of this, any user can access any question by just modifying the question ID in the URL. Without proper access checks, sensitive data may be exposed to unauthorized users. In more serious cases, attackers may also be able to modify or delete data belonging to other users.

How to fix:

Add an ownership check when accessing question detail view. Uncomment line 23 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L23) with the check, and comment out line 21 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L21). This verifies that the user requesting to see the question is authorized to do so.

#### FLAW 4:
A03:2021 Injection: user input is concatenated directly into SQL
Exact source link:
https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L125

Description:

The search endpoint directly concatenates the user’s input to the SQL query, allowing an attacker to inject harmful code. An SQL injection occurs when user input is interpreted as part of the SQL command. This allows an attacker to manipulate the database query executed by the application. In this application, searching with for example %' UNION SELECT id, username || ':' || password FROM auth_user -- returns all usernames and passwords from the database. Without proper sanitization or parameterization, the attacker can read sensitive data, modify database records, or even delete data.

How to fix:

Django provides a built-in ORM which automatically protects against SQL injection by using parameterized queries. To fix this vulnerability, replace the raw SQL with Django’s ORM search functionality. Uncomment line 133 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L133) and comment out lines 126-131 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/polls/views.py#L126).

#### FLAW 5:
A05:2021 Security Misconfiguration: DEBUG is hardcoded to True, exposing stack traces, settings, and environment details on errors
Exact source link:
https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/mysite/settings.py#L26

Description:

DEBUG is hardcoded to True, so when any unhandled error occurs, Django displays a detailed debug page with all settings and environment details to anyone. This information is meant to make development easier, and should never be exposed in a production environment. With the debug information, an attacker can see the internal structure of the application and identify vulnerabilities or configuration details.

How to fix:

Set the DEBUG value based on an environment variable, defaulting to False. Uncomment line 29 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/mysite/settings.py#L29) and comment out line 27 (https://github.com/avanine/cyber-security-course-project/blob/6cc500c17cf0fd2445d26262de998415bcac879d/mysite/settings.py#L27). Please note that you must also set ALLOWED_HOSTS when DEBUG is False, you can set it to for example ‘*’. This fix ensures that debug mode can be enabled in dev when needed, but is automatically disabled in production.
