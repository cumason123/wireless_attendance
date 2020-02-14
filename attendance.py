import pyshark as ps
import os
from threading import Thread
import queue
capture = ps.LiveCapture(interface='en0', display_filter='eapol')
identities = set()
packets_buffer = queue.Queue()


def update_users(identity_list='./identities.txt'):
	""" 
	Flushes identity strings to the identity_list file

	Parameters
	----------
	identity_list : str
		string representing filepath to flush identities to
	"""
	with open(identity_list, 'w') as file:
		file.write('\n'.join(identities))


def layer2identity(layer):
	"""
	Extracts identity header from a packet layer. Assumes layer
	has identity field.

	Parameters
	----------
	layer : obj
		layer object you can get from iterating through a pyshark packet
	"""
	identity = layer.get_field('identity')
	if not identity.endswith('@bu.edu'):
		identity += '@bu.edu'
	return identity


def packet_handler():
	"""
	Takes packets from a queue and outputs it to some filepath
	"""
	while True:
		print('Packet Thread waiting on buffer')
		packet = packets_buffer.get()
		print("Gotcha!", list(packet))
		for layer in packet:
			if ('identity' in layer.field_names):
				identity = layer2identity(layer)
				print("New Identity: {0}".format(identity))
				identities.add(identity)
				update_users()
			else:
				print('Identity not found in packet with: {0}'.format(layer))


def take_attendance():
	"""
	Logs attendance by sniffing packets on a 802 network and
	extracting identity headers from corresponding eapol protocol's. 
	"""
	packet_handler_thread = Thread(target=packet_handler)
	packet_handler_thread.start()
	while True:
		print("Sniffing for packets")
		capture.sniff(packet_count=1) # buggy setup separate thread to handle this stuff
		packets_buffer.put(capture[0])
		

if __name__ == '__main__':
	take_attendance()
