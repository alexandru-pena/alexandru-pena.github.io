---
layout: default
---


## Java Code Analysis!?!
 

**Description**

BookShelf Pico, my premium online book-reading service. I believe that my website is super secure. I challenge you to prove me wrong by reading the 'Flag' book! Here are the credentials to get you started:

    Username: "user"
    Password: "user"

Source code can be downloaded here. Website can be accessed here!.

**Write-up**

After starting the challenge, logged in with the provided credentials and looked around.
![alt text](image.png)
![alt text](image-1.png)

Web app provides a repository of pdf's, one of those is named "FLAG" and requires admin privilege to access.
![alt text](image-2.png)

Looked around the source code/assets and confirmed that the book "FLAG" contains the flag.
![alt text](image-3.png)

Looking around the code, noticed the authorization mechanism depends on the user "role" being equal or above the book "role".
![alt text](image-4.png)
![alt text](image-5.png)

The file "data.sql" defines 4 roles, "admin" being the highest.
![alt text](image-6.png)

App also implements a filter, executed before the API endpoint code, `doFilterInternal`. This endpoint will decode a JWT token and build a list of authorities which depends on the return value of `getRole`.
![alt text](image-7.png)

The role is extracted from the JWT token by the function `decodeToken` of the `JwtService` class.
![alt text](image-8.png)

Right above, the function `createToken` will build the user token, using as signing algorithm HMAC Sha 256 (HS256). The secret key used is returned by the function `getServerSecret` of the class `SecretGenerator`. The secret is hardcoded in the function `generateRandomString` as `1234`.
![alt text](image-9.png)

This means, that the JWT token is trivially forged. Using python, generated a fake token to login as "admin". 
![alt text](image-11.png)
![alt text](image-12.png)
![alt text](image-13.png)

Managed to login as admin and accessed the admin dashboard. Changed the user role freom "Free" to "Admin" and relogged back into the user account.
![alt text](image-14.png)
![alt text](image-15.png)

Obtained the flag:
![alt text](image-16.png)

**Solution**


Flag: picoCTF{w34k_jwt_n0t_g00d_7745dc02}


[back](./../..)