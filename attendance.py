import pyshark as ps
import os
capture = ps.LiveCapture(interface='en0', display_filter='eapol')
emails = set()

while True:
	print("Sniffing for packets")
	capture.sniff(packet_count=1)
	handler = open('bu-users.txt', 'w')
	for packet in capture:
		print("Gotcha!", list(packet))

		for layer in packet:
			if ('identity' in layer.field_names):
				email = layer.get_field('identity')
				if not email.endswith('@bu.edu'):
					email += '@bu.edu'
				print("New Identity: {0}".format(email))
				emails.add(email)
			else:
				print('Identity not found in packet with: {0}'.format(layer))
	handler.write('\n'.join(emails))
	handler.close()
