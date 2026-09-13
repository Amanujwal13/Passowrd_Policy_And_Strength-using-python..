"""

 Password policy and strength

"""
upp_count=0
low_count=0
dig_count=0
spec_count=0
special_char = "@#$%^&*!"


# user input..
password = input("Please Enter your password: ")


#stroing boolean value for the length_valid... 
length_valid = 8<= len(password) <=14


#Policy Block:- running the while loop till the use inters the password within the range of 8 and 14....
while not length_valid:    
        print("Please enter password at least of length above 8 and below 14!")   

        password = input("Please Enter your password: ")


#if the required length of the password matches then make the length_valid as True    
        if 8<= len(password) <=14:
             length_valid = True


#using for loop counting the letters wether they are upper, lower , digit or special characters...
for passw in password:
    if passw.isupper():
        upp_count+=1
    elif passw.islower():
        low_count+=1
    elif passw.isdigit():
        dig_count+=1
    elif passw in special_char:
        spec_count+=1  


# if the all the characters have met the requirement then print satisfied...
if upp_count >= 1 and low_count >= 1 and dig_count >= 1 and spec_count >= 1:
    print("All character requirements satisfied")
    

#creating a list of forbidden words...
forbidden = ["password", "12345", "qwerty", "admin", "username"]

forbidden_found = False


#running a for loop to check if the available forbidden word are not with the password..
for word in forbidden:
    if word in password.lower():
          print("Password should not contain forbidden words.")
          forbidden_found = True    # even one forbidden word is founded then break
          break;


# Counting Block:- We are printing every count in the password and providing how many letters nubers are there.
if length_valid:
     print(f'length_vaid : {length_valid}, PASS')
else:
     print("NOT PASS")     

if upp_count>=1:
     print(f'upp_count : {upp_count}, PASS')
else:
     print("NOT PASS")

if low_count>=1:
     print(f'low_count : {low_count}, PASS')
else:
     print("NOT PASS")    

if dig_count>=1:
    print(f'dig_count : {dig_count}, PASS')
else:
     print("NOT PASS")

if spec_count>=1:     
    print(f'spec_count : {spec_count}, PASS')          
else:print("NOT PASS")

if not forbidden_found:
     print(f'Forbidden found : {forbidden_found}, PASS')
else:
     print("NOT PASS") 

password_valid = True
if password_valid:
    print(f"Password_Valid : {password_valid}, PASS")
else:
    print(f"Password_Valid : {password_valid}, NOT PASS")


# Strength Block:- where we are checking on the basis of "Counting Block" wether the password comes in which category.. 
if upp_count >= 2 and low_count >= 2 and dig_count >= 2 and spec_count >= 2:
     print("Strength is Strong!")
elif upp_count >= 1 and low_count >= 1 and dig_count >= 1 and spec_count >= 1 and( upp_count >= 2 or low_count >= 2 or dig_count >= 2 or spec_count >= 2):
     print("Strength is High!")
elif upp_count >= 1 and low_count >= 1 and dig_count >= 1 and spec_count >= 1: 
     print("Strength is Moderate!")
else:
     print("Strength is Weak!")