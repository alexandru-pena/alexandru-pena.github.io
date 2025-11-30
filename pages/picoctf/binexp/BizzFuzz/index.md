---
layout: default
---


## Bizz Fuzz
 

**Description**

FizzBuzz was too easy, so I made something a little bit harder... There's a buffer overflow in this problem, good luck finding it! 


**Write-up**

Dynamic testing. Seems to be a variant of the game "FizzBuzz".
![alt text](image.png)
![alt text](image-2.png)

Protections.
![alt text](image-1.png)

Decompilation. The whole program code is a huge mess of nested if's.
![alt text](image-3.png)
![alt text](image-4.png)
![alt text](image-5.png)
![alt text](image-6.png)
![alt text](image-7.png)

This function, renamed to `func_2`, has a vulnerability in the `scanf` call as it writes off by 1 number. This input is supposed to receive the values "fizz", "buzz", "fizzbuzz", or number according to the rules of the FizzBuzz game. When this function terminates, it returns an integer to the functions above. This integer will be used in different places, and depending on it call `fgets` with different values to write to a buffer. One of those paths is probably vulnerable to buffer overflow.

If divisible by 15 => fizzbuzz, divisible by 5 => buzz, divisible by 3 => fizz. If none of those, to continue the game must insert same number as asked.
![alt text](image-8.png)

However, if current level is above the int passed to the function it also terminates.

First goal is to identify where the vulnerable `fgets` is, after this understand how to reach the code.

**Solution**


Flag: picoCTF{}


[back](/index)