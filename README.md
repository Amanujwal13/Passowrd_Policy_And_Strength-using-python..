Password policy and strength.....

Problem Statement------------------->>

Write a program that should return strength and a boolean value of whether the password is accepted or not.



The program structure--------------->>

Password
   |
   |-- Length?
   |-- Uppercase?
   |-- Lowercase?
   |-- Digit?
   |-- Special character?
   |-- Forbidden word?
   |
    Strength 
        |
        |-- Strong?
        |-- High?
        |-- Moderate?
        |-- Weak? 
   


Example---------------------->>

    |-> INPUT  : Gradious@123.

    |-> OUTPUT :    Please Enter your password:             
                    Gradious@123
                    All character requirements satisfied
                    length_vaid : True, PASS
                    upp_count : 1, PASS
                    low_count : 7, PASS
                    dig_count : 3, PASS
                    spec_count : 1, PASS
                    Forbidden found : False, PASS
                    Password_Valid : True, PASS
                    Strength is High!


How to Run----------------->>

Run the Python Program:-

Password_Policy_And_Strength.py

Then enter your password...


Project Structure---------------->>
-> Assingment_1
    |
    |-> Password_Policy_And_Strength.py
    |-> Password_Policy_And_Strength.txt
    |-> README.md
    |-> Screenshot 2026-09-08 150553.png


Expected Result------------------->>

    Please Enter your password: Gradious@123
    All character requirements satisfied
    length_vaid : True, PASS
    upp_count : 1, PASS
    low_count : 7, PASS
    dig_count : 3, PASS
    spec_count : 1, PASS
    Forbidden found : False, PASS
    Password_Valid : True, PASS
    Strength is High!