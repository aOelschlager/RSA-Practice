#!/usr/bin/env python
#
#  Anne-Marie Oelschlager
#  RSA.py
#	 Uses RSA to create a key pair and
#	 times the encryption and decryption
#	 of a block of plaintext. A loop is
#	 used to save the encryption and  
#	 decryption times and an average
#	 time is computed for each.
#

import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def main():
	tracking_file = "RSA.txt"
	# generate private and public key
	private_key = rsa.generate_private_key(65537, 2048, default_backend())
	public_key = private_key.public_key()
	
	trackFile = open(tracking_file, 'a')
	# plain text to encrypt and decrypt
	message = "secret message"
		
	i = 0
	ct_total = 0
	
	# a loop is used to save encryption times
	while i < 50:
		ct_before = time.clock()

		# encrypt with public key
		ciphertext = public_key.encrypt(message, padding.PKCS1v15())
	
		ct_after = time.clock()

		# ct_total saves and adds current encrypt time with total encrypt time 
		ct_total += (ct_after - ct_before)
		print "encryption loop: %s	time: %.30f" % (i, (ct_after - ct_before))
		trackFile.write("encryption loop: %s      time: %.30f\n" % (i, (ct_after - ct_before)))
		i += 1

	# ct_average saves the computed average of encryption time 
	ct_average = (ct_total / 50)
	print "\naverage encryption time is: %.30f\n" % (ct_average * 10 **6)
	trackFile.write("\naverage encryption time is: %.30f\n\n" % (ct_average * 10 ** 6))
	j = 0
	pt_total = 0
	
	# a loop is used to save decryption times
	while j < 50:
		pt_before = time.clock()

		# decrypt with private key
		plaintext =  private_key.decrypt(ciphertext, padding.PKCS1v15())
	
		pt_after = time.clock()

		# pt_total saves and adds current decrypt time with total decrypt time
		pt_total += (pt_after - pt_before)
		print "decryption loop: %s	time: %.30f " % (j, (pt_after - pt_before))
		trackFile.write("decryption loop: %s      time: %.30f\n" % (j, (pt_after - pt_before)))
		j += 1

	# pt_average saves the computed average of decryption time
	pt_average = (pt_total / 50)
	print "\naverage decryption time is: %.30f" % (pt_average * 10 **6)
	trackFile.write("\naverage decryption time is: %.30f\n" % (pt_average * 10 ** 6))

	print "\n\n---------private key encryption, public key decryption--------\n\n"
	trackFile.write("\n\n---------private key encryption, public key decryption--------\n\n\n")

	i = 0
	ct_total = 0
	
	# a loop is used to save encryption times
	while i < 50:
		ct_before = time.clock()

		# sign with private key
		signedtext = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
	
		ct_after = time.clock()

		# ct_total saves and adds current encrypt time with total encrypt time 
		ct_total += (ct_after - ct_before)
		print "encryption loop: %s	time: %.30f" % (i, (ct_after - ct_before))
		trackFile.write("encryption loop: %s      time: %.30f\n" % (i, (ct_after - ct_before)))
		i += 1

	# ct_average saves the computed average of encryption time 
	ct_average = (ct_total / 50)
	print "\naverage encryption time is: %.30f\n" % (ct_average * 10 ** 6)
	trackFile.write("\naverage encryption time is: %.30f\n\n" % (ct_average * 10 ** 6))
	j = 0
	pt_total = 0
	
	# a loop is used to save decryption times
	while j < 50:
		pt_before = time.clock()

		# verify with public key
		verifytext =  public_key.verify(signedtext, message, padding.PKCS1v15(), hashes.SHA256())
	
		pt_after = time.clock()

		# pt_total saves and adds current decrypt time with total decrypt time
		pt_total += (pt_after - pt_before)
		print "decryption loop: %s	time: %.30f " % (j, (pt_after - pt_before))
		trackFile.write("decryption loop: %s      time: %.30f\n" % (j, (pt_after - pt_before)))
		j += 1

	# pt_average saves the computed average of decryption time
	pt_average = (pt_total / 50)
	print "\naverage decryption time is: %.30f" % (pt_average * 10 ** 6)
	trackFile.write("\naverage decryption time is: %.30f\n" % (pt_average * 10 **6))
	trackFile.close()
	
	return 0

if __name__ == '__main__': 
	main()
