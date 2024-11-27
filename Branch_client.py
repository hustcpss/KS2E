#coding=utf-8

import LiuB_mod
import pymongo
import time
import pdb
import sys
import numpy as np
import json
import struct
import socket
import binascii
import threading
from pymongo import InsertOne

server_address = '127.0.0.1'
owner_last_keyword = {}
owner_last_fileid = {}
slice_of_cipher = 0
max_slice_of_cipher = 300
heap_of_slice = 1000000
last_hit_slice = dict()
EM_share_time = dict()
EM_share_time_latency = dict()

def write_cipher_to_db(ciphercol,data):
	#print(total_len)
	ciphercol.bulk_write(data,bypass_document_validation = False,ordered=False)

def send_data(sock, data):

	data['data'] = [ str(binascii.b2a_hex(element))[2:-1] for element in data['data']]

	data = json.dumps(data)
	sock.sendall(data.encode('ascii'))

def recv_data(sock):
	data = sock.recv(65535)
	data = data.decode('ascii')
	data = json.loads(data)
	data['data'] = [ bytes().fromhex(element) for element in data['data']]
	#pdb.set_trace()
	return data

def DB_Connect(test_db_name):
	global myclient,mydb,datadb,test_data,test_seq,owner_ciphercol,owner_internal,owner_slice_of_cipher
	print('Testing on  ', test_db_name)
	myclient = pymongo.MongoClient("mongodb://localhost:27017/?maxPoolSize=300&w=0")
	mydb = myclient["Branch"+test_db_name]
	owner_ciphercol = mydb["owner_ciphercol0"]
	owner_internal = mydb["owner_internal"]
	owner_slice_of_cipher = mydb["owner_slice"]
	owner_k = mydb["owner_key"]
	k = owner_k.find_one()
	k1 = k["1"]
	k2 = k["2"]
	k3 = k["3"]
	k4 = k["4"]
	#print(k1,k2,k3,k4)
	LiuB_mod.Restart(k1,k2,k3,k4)

def DB_Setup(test_db_name):
	global myclient,mydb,datadb,test_data,test_seq,owner_ciphercol,owner_internal,owner_slice_of_cipher
	myclient = pymongo.MongoClient("mongodb://localhost:27017/?maxPoolSize=300&w=0")
	mydb = myclient["Branch"+test_db_name]
	owner_internal = mydb["owner_internal"]
	owner_slice_of_cipher = mydb["owner_slice"]
	owner_k = mydb["owner_key"]
	for i in range(0,max_slice_of_cipher):
		owner_ciphercol = mydb["owner_ciphercol"+str(i)]
		owner_ciphercol.drop()
		owner_ciphercol.ensure_index('L',unique=True)
	owner_k.drop()
	owner_internal.drop()
	owner_slice_of_cipher.drop()
	dur,k1,k2,k3,k4 = LiuB_mod.Setup()
	#print(k1,k2,k3,k4)
	owner_k.insert_one({"1":k1,"2":k2,"3":k3,"4":k4})

def Encrypt(keywords,fileid):
	global owner_last_keyword,owner_last_fileid,fileids,keywords_set
	Keywords_Cipher = []
	fileindex_encrypted_time = 0
	for keyword in keywords:
		if fileid not in owner_last_keyword:
			last_keyword = ''
		else :
			last_keyword = owner_last_keyword[fileid]
		if keyword not in owner_last_fileid:
			last_fileid = ''
		else :
			last_fileid = owner_last_fileid[keyword]

		dur, L , I_w , R_w , C_w , I_id , R_id , C_id =LiuB_mod.Encrypt(keyword,fileid,last_keyword,last_fileid)

		fileindex_encrypted_time += dur
		Keywords_Cipher.append(InsertOne({'L':L,'Iw':I_w,'Rw':R_w,
				'Cw':C_w,'Iid':I_id,'Rid':R_id,'Cid':C_id}))

		owner_last_fileid[keyword] = fileid
		owner_last_keyword[fileid] = keyword

	return fileindex_encrypted_time, Keywords_Cipher
def write_encrypted_time(test_group,data):
	filename = open("./Result/"+test_group,'a')
	for d in data:
		filename.writelines(d)
	filename.close()

def write_internal_state(owner_last_keyword):
	global owner_internal
	owner_internal.drop()
	l = []
	for i in owner_last_keyword:
		l.append(InsertOne({"kw":i,"id":owner_last_keyword[i]}))
	owner_internal.bulk_write(l)

def read_internal_state():
	global owner_internal
	result = {}
	inte = owner_internal.find(no_cursor_timeout=True).batch_size(1000)
	for i in inte:
		result[i["kw"]]=i["id"]

	inte.close()
	return result

def write_slice_of_cipher(slice_of_cipher):
	global owner_slice_of_cipher
	owner_slice_of_cipher.drop()
	owner_slice_of_cipher.insert_one({"num":slice_of_cipher})

def read_slice_of_cipher():
	global owner_slice_of_cipher
	result = owner_slice_of_cipher.find_one()
	return result["num"]

def Ciphertext_Gen_Phase():
	global myclient,owner_ciphercol,owner_internal,slice_of_cipher

	plaintextdb = myclient[test_db_name]
	plaintext_col = plaintextdb["id_keywords_filter"]

	#when test emit this debug mode
	plaintext_cur = plaintext_col.find(no_cursor_timeout=True).batch_size(1000)
	upload_list = []
	upload_list_len = 0
	total_len = 0
	last_total_len = 0
	Ciphertext_Gen_Phase_time = 0
	heap_of_slice =1000000
	result = []
	owner_ciphercol = mydb["owner_ciphercol"+str(slice_of_cipher)]

	for plaintext in plaintext_cur:

		encrypted_time , Keywords_Cipher = Encrypt(plaintext['kset'],plaintext['fid'])
		Ciphertext_Gen_Phase_time += encrypted_time
		upload_list.extend(Keywords_Cipher)			

	# check code
		total_len += len(Keywords_Cipher)
		if total_len > last_total_len:
			last_total_len += 100000
			result.append('len:\t'+str(total_len) +'\t'+ str(Ciphertext_Gen_Phase_time)+'\n')
			if len(result) > 100:
				print('wirtedata')
				write_encrypted_time("Encrypt"+test_group,result)
				result = []
	# check code

	# result code
		if total_len >= heap_of_slice:
			heap_of_slice+= 1000000
			slice_of_cipher+=1
			owner_ciphercol = mydb["owner_ciphercol"+str(slice_of_cipher)]
			print("start slice, check dic\t",len(owner_last_keyword),'\t',len(owner_last_fileid))
	# result code
	# update code
		if len(upload_list) > 200000:
			t=threading.Thread(target=write_cipher_to_db,args=(mydb["owner_ciphercol"+str(slice_of_cipher)],upload_list[:]))
			t.start()
			upload_list = []

	if len(upload_list)  > 0:
		owner_ciphercol.bulk_write(upload_list,ordered=False)
	if len(result) > 0:
		write_encrypted_time("Encrypt"+test_group,result)
	# update code

	plaintext_cur.close()
	write_internal_state(owner_last_keyword)
	write_slice_of_cipher(slice_of_cipher)
	
	print(slice_of_cipher)

	return slice_of_cipher,Ciphertext_Gen_Phase_time


class MyThread(threading.Thread):
	def __init__(self, func, args=()):
		super(MyThread, self).__init__()
		self.func =func
		self.args = args
	def run(self):
		self.result = self.func(*self.args)
	def get_result(self):
		threading.Thread.join(self)
		try:
			return self.result
		except Exception:
			pdb.set_trace()
			return None

def thread_find(coll,L_id,i):
	return i,coll.find_one({'L':L_id})

def complex_thread_find(slice_of_cipher,L_id):
	global last_hit_slice
	if L_id in last_hit_slice:
		return last_hit_slice[L_id]
	else:	
		result = {}
		p = [MyThread(thread_find,(mydb["owner_ciphercol"+str(i)],L_id,i)) for i in range(0,slice_of_cipher+1)]
		#pdb.set_trace()
		for t in p:
			t.start()
		for t in p:
			t.join()
		for t in p:
			hit,result = t.get_result()
			if result is not None:
				last_hit_slice = dict()
				hp = mydb["owner_ciphercol"+str(hit)]
				hpt = hp.find()
				for rs in hpt:
					last_hit_slice[rs['L']] = rs
				break
		return result

def write_em_share_time(test_group,EM_share_time,EM_share_time_latency):
	filename = open("./Result/EmShare"+test_group,'w')
	for ke in EM_share_time:
		filename.writelines('len:\t'+str(ke) +'\t'+ str(np.mean(EM_share_time[ke]))+'\t'+ str(np.mean(EM_share_time_latency[ke]))+'\n')

	filename.close()

def Derive_Phase():
	global owner_ciphercol,owner_last_keyword,myclient,fileids,owner_internal,EM_share_time

#	read internal and data

	owner_last_keyword = read_internal_state()
	slice_of_cipher = read_slice_of_cipher()

#	read internal and data
	total_len = 0
	last_total_len = 0

	for fileid in owner_last_keyword :

		time_of_the_file = 0
		time_of_the_file_lantency = 0

		keyword = owner_last_keyword[fileid]

		dur, L_id, J_id, k_id = LiuB_mod.Derivedkey(keyword,fileid)


		t1 = time.time()
		edge_manager_send_share_key([L_id,J_id,fileid.encode('ascii'),k_id])

		
		re = complex_thread_find(slice_of_cipher,L_id)
		t2 = time.time()

		time_of_the_file += dur
		time_of_the_file_lantency += (t2-t1)

		Keywords_Cipher = []

		while L_id[0]!=0 or L_id[1]!=0 or L_id[2]!=0 or L_id[3]!=0 or L_id[4]!=0:
			re = complex_thread_find(slice_of_cipher,L_id)
			Keywords_Cipher.append(re['Cid'])
			dur,L_id ,J_id = LiuB_mod.XortoNext(J_id,re['Rid'],re['Iid'])

			time_of_the_file += dur
		if len(Keywords_Cipher) not in EM_share_time:
			EM_share_time[len(Keywords_Cipher)] = []
			EM_share_time_latency[len(Keywords_Cipher)] = []
		EM_share_time[len(Keywords_Cipher)].append(time_of_the_file)
		EM_share_time_latency[len(Keywords_Cipher)].append(time_of_the_file_lantency)
		edge_manager_send_ciphertext(Keywords_Cipher)

	write_em_share_time(test_group,EM_share_time,EM_share_time_latency)

def Search_Phase():
	edge_manager_send_search_request([b'start',])

def edge_manager_send_share_key(messagedata):
	global server_address
	sock = socket.socket()
	address = (server_address, 18041)
	sock.connect(address)
	send_data(sock,{'function':'send_file_key','data':messagedata})
	sock.close()

def edge_manager_send_ciphertext(messagedata):
	global server_address
	sock = socket.socket()
	address = (server_address, 18041)
	sock.connect(address)
	send_data(sock,{'function':'send_file_index','data':messagedata})
	sock.close()

def edge_manager_send_search_request(messagedata):
	global server_address
	sock = socket.socket()
	address = (server_address, 18041)
	sock.connect(address)
	send_data(sock,{'function':'send_search_token','data':messagedata})
	sock.close()

def Test():
	l = list(test_phase)
	print ('*********************************************')
	print ('start test_group', test_group)
	if 'b' in l:
		print('start initial db')
		DB_Setup(test_db_name)
	else:
		DB_Connect(test_db_name)

	if 'c' in l:
		print('start encrypt')
		Ciphertext_Gen_Phase()
	if 'd' in l:
		print('start share')
		Derive_Phase()
	if 's' in l:
		print('start search')
		Search_Phase()

if __name__ == "__main__":

		test_db_name = str(sys.argv[1])
		test_phase = str(sys.argv[2])
		test_group = str(sys.argv[3])
		fileids =[]
		keywords_set = []
		Test()

