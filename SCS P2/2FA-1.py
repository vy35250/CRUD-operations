import os
import sys
import re
from passlib.hash import sha512_crypt

SHADOW_FILE = '/etc/shadow'
PASSWD_FILE = '/etc/passwd'
class User:
    def __init__(self, username, password, current_token, salt):

        # Check if the user already exists during object creation
        if self.user_exists(username):
            print("FAILURE: user " + username + " already exists")
            sys.exit()

        self.username = username
        self.password = password
        self.current_token = current_token
        self.salt = salt
        self.hashed_password = sha512_crypt.hash(password + current_token, salt_size=8, salt=salt, rounds=5000)

        # Add the user to the OS
        self.update_passwd_file()
        self.update_shadow_file()
        self.create_home_directory()
        print("SUCCESS: " + username + " created")

    @staticmethod
    def user_exists(username):
        with open(SHADOW_FILE, 'r') as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        with open(PASSWD_FILE, 'r') as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        return False

    def update_passwd_file(self):
        count = 1000

        with open(PASSWD_FILE, 'r') as f:
            for line in f:
                temp1 = line.split(':')
                while count <= int(temp1[3]) < 65534:
                    count = int(temp1[3]) + 1
        count = str(count)

        passwd_line = f"{self.username}:x:{count}:{count}:,,,:/home/{self.username}:/bin/bash"

        with open(PASSWD_FILE, 'a+') as passwd_file:
            passwd_file.write(passwd_line + '\n')

    def update_shadow_file(self):
        shadow_line = f"{self.username}:{self.hashed_password}:17710:0:99999:7:::"
        with open(SHADOW_FILE, 'a+') as shadow_file:
            shadow_file.write(shadow_line + '\n')

    def create_home_directory(self):
        try:
            os.mkdir("/home/" + self.username)
        except FileExistsError:
            print("Directory: /home/" + self.username + " already exists")

    def __str__(self):
        return (f"Username:\t{self.username}\nPassword:\t{self.password}\nSalt:\t\t{self.salt}\n"
                f"Hash:\t\t{self.hashed_password}")


class User_check:
    def __init__(self, username, password, current_token):
        self.username = username
        self.password = password
        self.current_token = current_token

    def authenticate(self, next_token):
        """Authenticate the user."""
        with open(SHADOW_FILE, 'r') as file:
            lines = file.readlines()

        for i in range(len(lines)):
            temp = lines[i].split(':')
            if temp[0] == self.username:
                salt_and_pass = temp[1].split('$')
                salt = salt_and_pass[2]
                # Calculate hash using the retrieved salt and the password
                calculated_hash = sha512_crypt.hash(self.password + self.current_token, salt_size=len(salt), salt=salt, rounds=5000)
                if calculated_hash == temp[1]:
                    new_hash = sha512_crypt.hash(self.password + next_token, salt_size=len(salt), salt=salt, rounds=5000)
                    temp[1] = new_hash
                    lines[i] = ":".join(temp)
                    with open(SHADOW_FILE, 'w') as file:
                        file.writelines(lines)
                    print("SUCCESS: Login Successful")
                else:
                    print("FAILURE: either passwd or token incorrect")
                return
        print("FAILURE: user " + self.username + " does not exist")

    def update_password(self, next_token, new_salt, new_password):
        with open(SHADOW_FILE, 'r') as file:
            lines = file.readlines()

        for i in range(len(lines)):
            temp = lines[i].split(':')
            if temp[0] == self.username:
                salt_and_pass = temp[1].split('$')
                salt = salt_and_pass[2]
                # Calculate hash using the retrieved salt and the password
                calculated_hash = sha512_crypt.hash(self.password + self.current_token, salt_size=len(salt), salt=salt, rounds=5000)
                if calculated_hash == temp[1]:
                    new_hash = sha512_crypt.hash(new_password + next_token, salt_size=len(new_salt), salt=new_salt, rounds=5000)
                    temp[1] = new_hash
                    lines[i] = ":".join(temp)
                    with open(SHADOW_FILE, 'w') as file:
                        file.writelines(lines)
                    print("SUCCESS: user " + self.username + " updated")
                else:
                    print("FAILURE: either passwd or token incorrect")
                return
        print("FAILURE: user " + self.username + " does not exist")

    def delete_user(self):
        userfound = False
        userdel = False
        with open(SHADOW_FILE, 'r') as file:
            lines = file.readlines()

        for i in range(len(lines)):
            temp = lines[i].split(':')
            if temp[0] == self.username:
                userfound = True
                salt_and_pass = temp[1].split('$')
                salt = salt_and_pass[2]
                # Calculate hash using the retrieved salt and the password
                calculated_hash = sha512_crypt.hash(self.password + self.current_token, salt_size=len(salt), salt=salt, rounds=5000)
                if calculated_hash == temp[1]:
                    del lines[i]
                    os.rmdir("/home/" + self.username)
                    with open(SHADOW_FILE, 'w') as file:
                        file.writelines(lines)
                    print("SUCCESS: user " + self.username + " Deleted")
                    userdel = True
                else:
                    print("FAILURE: either passwd or token incorrect")
                break
        if not userfound:
            print("FAILURE: user " + self.username + " does not exist")
        
        if not userdel:
            return
        
        with open(PASSWD_FILE, 'r') as file:
            lines = file.readlines()
        
        for i in range(len(lines)):
            temp = lines[i].split(':')
            if temp[0] == self.username:
                del lines[i]
                with open(PASSWD_FILE, 'w') as file:
                    file.writelines(lines)
                    return

def get_option():
    prompt = "Select an action:\n1) Create a user\n2) Login\n3) Update password\n4) Delete user account\n"
    option = input(prompt)
    return option


def create_user():
    username = input("Username: ")
    password = input("Password: ")
    confirm_password = input("Confirm Password: ")
    salt = input("Salt: ")
    initial_token = input("Initial Token: ")
    if password != confirm_password:
        print("Password and Confirm password don't match try again.")
        return
    user = User(username, password, initial_token, salt)

def login():
    username = input("Username: ")
    password = input("Password: ")
    current_token = input("Current Token: ")
    next_token = input("Next Token: ")
    user = User_check(username, password, current_token)
    user.authenticate(next_token)

def update_password():
    username = input("Username: ")
    password = input("Password: ")
    new_password = input("New Password: ")
    confirm_new_password = input("Confirm New Password: ")
    new_salt = input("New Salt: ")
    current_token = input("Current Token: ")
    next_token = input("Next Token: ")

    if new_password != confirm_new_password :
        print("New password and confirm new password must match")

    user = User_check(username, password, current_token)
    user.update_password(next_token, new_salt, new_password)

def delete_user():
    username = input("Username: ")
    password = input("Password: ")
    current_token = input("Current Token: ")
    user = User_check(username, password, current_token)
    user.delete_user()

def main():
    option = get_option()
    if option == "1":
        create_user()
    elif option == "2":
        login()
    elif option == "3":
        update_password()
    elif option == "4":
        delete_user()
    else:
        print("Invalid option. Try again")


if __name__ == '__main__':
    main()