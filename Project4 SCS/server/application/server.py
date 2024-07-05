import base64
import os
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from os import urandom
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json

# TODO: import additional modules as required


secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)
dict={}
class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"

def verify_statement(statement, signed_statement, user_public_key_file):
    with open(user_public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend = default_backend())
    try:
        public_key.verify(
        signed_statement,
        statement.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
            )
        return True
    except Exception as e:
        print(e)
        return False




class login(Resource):
    def post(self):
        data = request.get_json()
        # TODO: Implement login functionality
        '''
            # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
            Expected response status codes:
            1) 200 - Login Successful
            2) 700 - Login Failed
        '''
        # Information coming from the client
        user_id = data['user-id']
        statement = data['statement']
        signed_statement = base64.b64decode(data['signed-statement'])

        # complete the full path of the user public key filename
        # /home/cs6238/Desktop/Project4/server/application/userpublickeys/{user_public_key_filename}
        user_public_key_file = '/home/cs6238/Desktop/Project4/server/application/userpublickeys/' + user_id + '.pub'


        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:
            session_token = secrets.token_hex(16)
          #  print(session_token)
            dict[user_id]= session_token
           # print(dict)

            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }
        else:
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        return jsonify(response)


class checkin(Resource):

    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        token = data['token']
        with open("/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        user = ""
        for key in dict.keys():
            if dict[key] == token:
                user = key

        print(user)  # it will print the logged in user

        doc_id = data['DID']
        file_data = data['file_data']
        print(file_data)
        security_flag = data['security_flag']
        json_filename = f"documents/{doc_id}.json"
        if os.path.exists(json_filename):
            print(" im in bigg if")
            with open(json_filename, 'r') as file:
                json_data = json.load(file)
            print(json_data)
            owner = json_data['owner']
            print(owner)
            grant_users = json_data.get('grant_users', [])
            file_data = data['file_data']
           # security_flag = data['security_flag']
            print(security_flag)
            aes_key = json_data['aes_key']
            print(grant_users)
            grant_access = json_data.get('grant_access', [])
            print("Grant Access Raw Data:", grant_access)

            grant_access_value = ','.join(map(str, grant_access))

            print("grant access values:", grant_access_value)
            users_string = ', '.join(user['username'] for user in grant_users if 'username' in user)
            print("Users as String:", users_string)
            current_time = int(time.time())
            print(current_time)
            grant_exp_list = json_data.get('grant_exp', [])
            print(grant_exp_list)
            grant_exp_raw = json_data.get('grant_exp', None)
            print(grant_exp_raw)
            #grant_users = json_data.get('grant_user', [])
            grant_access = json_data.get('grant_access', [])
            #grant_exp = json_data.get('grant_exp', [])
            # grant_exp = int(grant_exp_list[0])
            # grant_exp_list = data.get('grant_exp', [])
            # Assuming grant_exp_raw can be None, a string, an integer, or a list containing a string or integer
            if grant_exp_raw is None:
                grant_exp = 0
            else:
                grant_exp = next(
                    (int(item) for item in ([grant_exp_raw] if isinstance(grant_exp_raw, (int, str)) else grant_exp_raw) if
                    isinstance(item, int) or (isinstance(item, str) and item.isdigit())), None)

            # Safely access the first item of the list if it exists, otherwise set to None or a default value
           # grant_exp = int(grant_exp_raw[0]) if isinstance(grant_exp_raw, list) else int(grant_exp_raw) if grant_exp_raw is not None else None

            print("Grant Expiry Timestamp:", grant_exp)

            success = False
            if ((user == owner) and security_flag == 1) or (( ((user in users_string or "0" in users_string) and (grant_access_value == '3') ) or ( (user in users_string or "0" in users_string) and (grant_access_value == '1') )) and (current_time < grant_exp)):
                print("i am in iff of checkin")

                filename = doc_id + ".json"

              #  owner = user
               # filename = f"documents/{doc_id}.json"
                    # Construct the filename from the document ID


                # Metadata to be saved
                metadata = {
                    'doc_id': doc_id,
                    'owner': owner,
                    'security_flag': security_flag,
                    'grant_users': grant_users,
                    'grant_access' : grant_access,
                    'grant_exp': grant_exp,
                    'aes_key' : aes_key

                }


                # Writing the metadata to a JSON file
                with open("documents/" + filename, 'w') as file:
                    json.dump(metadata, file, indent=4)


                #print(metadata)

            #if security_flag == 1:

                # Generate a random AES key and IV
                aes_key = os.urandom(32)  # 256-bit AES key
                iv = os.urandom(16)  # AES IV
                file_data_bytes = file_data.encode('utf-8')

                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                # Pad the file data
                padder = PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(file_data_bytes) + padder.finalize()

                # Encrypt the padded data
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

                with open('documents/' + doc_id, 'wb') as encrypted_file:
                    encrypted_file.write(iv + encrypted_data)


                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )

                )
               # print(encrypted_aes_key)
                metadata['aes_key'] = encrypted_aes_key.hex()  # Store as hex for readability

                # Update the metadata file
                with open("documents/" + filename, 'w') as file:
                    json.dump(metadata, file, indent=4)
                success = True
                # print((current_time < grant_exp))


            elif ((user == owner) and security_flag == 2)  or ((( (user in users_string or "0" in users_string) and (grant_access_value == '3') ) or ( (user in users_string or "0" in users_string) and (grant_access_value == '1') )) and (current_time < grant_exp)):
                print("i m in else of intergrity checkin")
                #input_file_path = 'path_to_your_file.txt'

                # Path to the server's private key file
                private_key_path = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key'
                filename = doc_id + ".sign"
               # normal_file = doc_id


                # Read the private key
                with open(private_key_path, 'rb') as key_file:
                    #key_data = key_file.read()
                  #  print(key_data)
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,  # Change this if your key is password-protected
                        backend=default_backend()
                    )
                if isinstance(file_data, str):
                    file_data = file_data.encode('utf-8')

                signature = private_key.sign(
                    file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                with open("documents/" + filename, 'wb') as file:
                    file.write(signature)
                with open("documents/" + doc_id, "w") as file:
                    file.write(data['file_data'])

                success = True

        else:
            #print("in else of confidentiality checkin")
            print(user)
            filename = doc_id + ".json"
            metadata = {
                'doc_id': doc_id,
                'owner': user,
                'security_flag': security_flag,
                'grant_users': "",
                'grant_access': "",
                'grant_exp': "",
                'aes_key': ""

            }
            with open("documents/" + filename, 'w') as file:
                json.dump(metadata, file, indent=4)

            if security_flag == 1:

                aes_key = os.urandom(32)  # 256-bit AES key
                iv = os.urandom(16)  # AES IV
                file_data_bytes = file_data.encode('utf-8')

                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                # Pad the file data
                padder = PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(file_data_bytes) + padder.finalize()

                # Encrypt the padded data
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

                with open('documents/' + doc_id, 'wb') as encrypted_file:
                    encrypted_file.write(iv + encrypted_data)

                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )

                )
                # print(encrypted_aes_key)
                metadata['aes_key'] = encrypted_aes_key.hex()  # Store as hex for readability

                # Writing the metadata to a JSON file
                with open("documents/" + filename, 'w') as file:
                    json.dump(metadata, file, indent=4)
                success = True



            elif security_flag == 2:
                print("in else of integrity")
                private_key_path = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key'
                filename = doc_id + ".sign"
                file_data = data['file_data']

                # normal_file = doc_id

                # Read the private key
                with open(private_key_path, 'rb') as key_file:
                    # key_data = key_file.read()
                    #  print(key_data)
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,  # Change this if your key is password-protected
                        backend=default_backend()
                    )
                if isinstance(file_data, str):
                    file_data = file_data.encode('utf-8')

                signature = private_key.sign(
                    file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                with open("documents/" + filename, 'wb') as file:
                    file.write(signature)
                with open("documents/" + doc_id, "w") as file:
                    file.write(data['file_data'])
                success = True


        if success:

            response = {
                        'status': 200,
                        'message': 'Document Successfully checked in',
                 }
        else:
            response = {
                    'status': 702,
                    'message': 'Access denied checking in',
                }
        return jsonify(response)


class checkout(Resource):
    """
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """
    def post(self):

        data = request.get_json()
        token = data['token']
        user = ""
        for key in dict.keys():
            if dict[key] == token:
                user = key
        #print(user)
        doc_id = data['DID']
        #print(doc_id)
        file_path = f"documents/{doc_id}.json"
        normal_file = f"documents/{doc_id}"
        print(file_path)# Modify the extension if necessary
        # Check if the file exists
       # success = False
        # if os.path.exists(file_path):
        doc_id = data['DID']

        json_filename = f"documents/{doc_id}.json"
        if os.path.exists(json_filename):
            with open(json_filename, 'r') as file:
                json_data = json.load(file)
            # print(json_data)
            owner = json_data['owner']
            print(owner)
            grant_users = json_data.get('grant_users', [])
            #file_data = data['file_data']
            security_flag = json_data['security_flag']
            aes_key = json_data['aes_key']
            print(grant_users)
            # Extract usernames using a list comprehension
            usernames = [user1['username'] for user1 in grant_users]
            # grant_users = [user1['username'] for user1 in json_data['grant_users']]
            usernames_str = ', '.join(map(str, usernames))
            print(usernames_str)
            current_time = int(time.time())
            print(current_time)
            grant_exp_list = json_data.get('grant_exp', [])
            print(grant_exp_list)
            grant_exp_raw = json_data.get('grant_exp', None)
            grant_users = json_data.get('grant_users', [])
            grant_access = json_data.get('grant_access', [])
            print("Grant Access Raw Data:", grant_access)

            grant_access_value = ','.join(map(str,grant_access))

            print("grant access values:", grant_access_value)
            # Safely access the first item of the list if it exists, otherwise set to None or a default value
            #grant_exp = int(grant_exp_raw[0]) if isinstance(grant_exp_raw, list) else int(grant_exp_raw) if grant_exp_raw is not None else None
            if grant_exp_raw is None:
                grant_exp = 0
            else:
                grant_exp = int(grant_exp_raw[0]) if isinstance(grant_exp_raw, list) and grant_exp_raw and grant_exp_raw[0] != '' else int(grant_exp_raw) if grant_exp_raw not in (None, '') and not isinstance(grant_exp_raw,list) else None

            print("Grant Expiry Timestamp:", grant_exp)

            success = False
            if  ((user == owner)  or (( ((user in usernames_str or "0" in usernames_str) and (grant_access_value == '3') ) or ( (user in usernames_str or "0" in usernames_str) and (grant_access_value == '2') )) and (current_time < grant_exp))) and security_flag == 1:
                print("i am in iff of checkout")
                print(f"File exists: {file_path}")

                # = "/path/to/directory/doc_id.json"  # Path to the JSON file storing the encrypted AES key
                private_key_path = "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key"  # Server's private key path

                # Read the encrypted AES key from the JSON file
                with open(file_path, 'r') as file:
                    data = json.load(file)
                    encrypted_aes_key_hex = data['aes_key']  # Assuming the key is stored as hex in the JSON
                    encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)  # Convert hex to bytes

                # Load the private RSA key
                with open(private_key_path, 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,  # Provide the password here if the key is encrypted
                        backend=default_backend()
                    )

                # Decrypt the AES key
                decrypted_aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                #decrypted_aes_key = bytes(encrypted_aes_key)
                print("Decrypted AES Key:", decrypted_aes_key)# Replace this with your actual decrypted AES key

                # Read the encrypted data from the file
                encrypted_file_path = f'/home/cs6238/Desktop/Project4/server/application/documents/{doc_id}'
                decrypted_file_path = f'/home/cs6238/Desktop/Project4/server/application/documents/{doc_id}'

                #print(encrypted_file_path)
                with open(encrypted_file_path, 'rb') as file:
                    # Assuming the IV is the first 16 bytes, adjust if your IV size is different
                    iv = file.read(16)
                    encrypted_data = file.read()
                    #print(iv)

                # Setup cipher for decryption
                cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                # Decrypt the data
                padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

                # Remove padding if padding was applied during encryption
                unpadder = PKCS7(algorithms.AES.block_size).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

                # Write the decrypted data to a new file

                # with open(decrypted_file_path, 'wb') as decrypted_file:
                #     decrypted_file.write(plaintext)
                #     print("Decryption complete. Decrypted data written to:", decrypted_file_path)
                success = True
            elif  ((user == owner)  or (( ((user in usernames_str or "0" in usernames_str) and (grant_access_value == '3') ) or ( (user in usernames_str or "0" in usernames_str) and (grant_access_value == '2') )) and (current_time < grant_exp))) and security_flag == 2:

                    # Paths to the necessary files and keys
                public_key_path = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub'
                signature_file_path = f"documents/{doc_id}.sign"
                normal_file = f'/home/cs6238/Desktop/Project4/server/application/documents/{doc_id}'

                with open(normal_file, 'rb') as file:
                    file_data = file.read()

                    # Load the public key
                with open(public_key_path, 'rb') as key_file:
                    public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                        )

                    # Load the signature
                with open(signature_file_path, 'rb') as file:
                    signature = file.read()

                try:
                    public_key.verify(
                        signature,
                        file_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                            ),
                        hashes.SHA256()
                        )
                    print("Signature is valid.")
                    success = True
                except Exception as e:
                    print("Signature is invalid:", str(e))
                    success = False
                    response = {
                        'status': 703,
                        'message': 'Check out failed due to broken integrity',
                        'file': 'Invalid'
                    }
                    return jsonify(response)
                plaintext = file_data

            if success:
                    # Similar response format given below can be
                    # used for all the other functions
                    response = {
                        'status': 200,
                        'message': 'Document Successfully checked out',
                        'file': plaintext.decode('utf-8')
                    }
            else:
                    response = {
                        'status': 702,
                        'message': 'Access denied checking out',
                        'file': 'Invalid'
                    }
            print(response)
            return jsonify(response)
        else:
            response = {
                'status': 704,
                'message': 'Check out failed since file not found on the server',
                'file': 'Invalid'
            }
            print(response)
            return jsonify(response)

class grant(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """
    def post(self):
        try:
            req_data = request.get_json()
            token = req_data['token']
            user = ""
            for key in dict.keys():
                if dict[key] == token:
                    user = key
            print(user)
            print("aBXD")

            doc_id = req_data['DID']
            # Construct the filename from the document ID
            json_filename = f"documents/{doc_id}.json"
            with open(json_filename, 'r') as file:
                data = json.load(file)
            print(data)
            owner = data.get('owner')
            print(owner)
            grant_users = req_data.get('grant_users', [])
            grant_access = req_data.get('grant_access', [])
            grant_exp = req_data.get('grant_exp', [])

            security_flag = data.get('security_flag')
            aes_key = data.get("aes_key")

            # Prepare the metadata
            metadata = {
                'doc_id': doc_id,
                'owner': user,
                'security_flag': security_flag,
                'grant_users': grant_users,
                'grant_access': grant_access,
                'grant_exp': grant_exp,
                'aes_key': aes_key
            }
            filename = doc_id + ".json"
            if owner == user:
                print("I'm in if")

                try:
                    with open(json_filename, 'w') as file:
                        json.dump(metadata, file, indent=4)
                    response = {
                        'status': 200,
                        'message': 'Successfully granted access',
                    }
                except IOError as e:
                    response = {
                        'status': 700,
                        'message': 'Failed to write metadata: ' + str(e)
                    }
            else:
                response = {
                    'status': 702,
                    'message': 'Access denied to grant access',
                }

            return jsonify(response)
        except:
            response = {
                'status': 700,
                'message': 'Other failures',
            }

            return jsonify(response)

class delete(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
    """
    def post(self):

        data = request.get_json()
        token = data['token']
        user = ""
        for key in dict.keys():
            if dict[key] == token:
                user = key
        print(user)
        doc_id = data['DID']
        print(doc_id)
        file_path = f"documents/{doc_id}.json"
        normal_file = f"documents/{doc_id}"
        sign_file = f"documents/{doc_id}.sign"
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
            owner = data.get('owner')
            print(f"Owner: {owner}")

            if user != owner:
                print("User is not the owner, cannot delete the file.")
                response = {
                    'status': 702,
                    'message': 'Access denied deleting file',
                }
            elif not os.path.exists(normal_file):
                print(f"File does not exist: {normal_file}")
                response = {
                    'status': 704,
                    'message': 'Delete failed since file not found on the server'
                }
            else:
                os.remove(normal_file)
                os.remove(file_path)
                try:
                    os.remove(sign_file)
                except:
                    pass
                print(f"File {normal_file} has been deleted successfully.")
                response = {
                    'status': 200,
                    'message': 'Successfully deleted the file',
                }
        except FileNotFoundError:
            print(f"The file {file_path} does not exist.")
            response = {
                'status': 704,
                'message': 'Delete failed since file not found on the server'
            }
        except json.JSONDecodeError:
            print(f"Error decoding JSON from the file {file_path}.")
            response = {
                'status': 700,
                'message': 'Other failures'
            }
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            response = {
                'status': 700,
                'message': 'Other failures'
            }
        return jsonify(response)

class logout(Resource):
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """
        data = request.get_json()
        token = data['token']
        user = ""
        for key in dict.keys():
            if dict[key] == token:
                print("if")
                user = key
        print(user)
        print(dict)# this will give me logged in user
        # print("logout out")
        if user:
            del dict[user]
            print(user, "logged out")
            response = {
                'status': 200,
                'message': 'Successfully logged out.'
            }
        else:
            response = {
                'status': 702,
                'message': 'Failed to logout.'
            }
        return jsonify(response)
api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')


def main():
    secure_shared_service.run(debug=True)


if __name__ == '__main__':
    main()
