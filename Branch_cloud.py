#coding=utf-8

import LiuB_mod
import pymongo
import time
import pdb
import sys
import json
import struct
import socket
import numpy as np
import binascii
import threading
from pymongo import InsertOne

user_last_fileid = {}
keywords_space = dict()
slice_of_cipher = 0
max_slice_of_cipher = 300
Upload_Derive_Cipher = []
Upload_Derive_Cipher_len = 0
heap_of_slice = 1000000
CM_share_time = dict()
CM_search_time_latency = dict()
last_hit_slice = dict()
current_hit_slice = 301

def send_data(conn, data):
	data['data'] = [ str(binascii.b2a_hex(element))[2:-1] for element in data['data']]
	data = json.dumps(data)
	conn.sendall(data.encode('ascii'))

def recv_data(conn):
	#pdb.set_trace()
	total_data =[]
	while True:
		data = conn.recv(20480)
		if not data:
			break
		total_data.append(data)
	total_data = [i.decode('ascii') for i in total_data]
	data = ''.join(total_data)
	data = json.loads(data)
	data['data'] = [ bytes().fromhex(element) for element in data['data']]
	return data

def DB_Connect(test_db_name):
	global myclient,mydb,datadb,task_search_list,user_ciphercol,user_internal,user_slice_of_cipher
	print('Testing on  ', test_db_name)
	LiuB_mod.Setup()
	myclient = pymongo.MongoClient("mongodb://localhost:27017/?maxPoolSize=300&w=0")
	mydb = myclient["Branch"+test_db_name]
	user_ciphercol = mydb["user_ciphercol0"]
	user_internal = mydb["user_internal"]
	user_slice_of_cipher =mydb["user_slice"]
	task_search_list = mydb["task_search_list"]
	user_k = mydb["user_key"]
	k = user_k.find_one()
	k1 = k["1"]
	k2 = k["2"]
	k3 = k["3"]
	k4 = k["4"]
	LiuB_mod.Restart(k1,k2,k3,k4)

def DB_Setup(test_db_name):
	global myclient,mydb,datadb,test_data,test_seq,user_ciphercol,user_internal,user_slice_of_cipher,task_search_list

	myclient = pymongo.MongoClient("mongodb://localhost:27017/?maxPoolSize=300&w=0")
	mydb = myclient["Branch"+test_db_name]

	user_internal = mydb["user_internal"]
	user_slice_of_cipher =mydb["user_slice"]
	task_search_list = mydb["task_search_list"]
	user_k = mydb["user_key"]

	for i in range(0,max_slice_of_cipher):
		user_ciphercol = mydb["user_ciphercol"+str(i)]
		user_ciphercol.drop()
		user_ciphercol.ensure_index('L',unique=True)

	user_internal.drop()
	user_slice_of_cipher.drop()
	task_search_list.drop()
	user_k.drop()

	dur,k1,k2,k3,k4 = LiuB_mod.Setup()
	user_k.insert_one({"1":k1,"2":k2,"3":k3,"4":k4})

def read_keyword_space():
	global task_search_list
	result = []
	task_search = task_search_list.find(no_cursor_timeout=True)
	for t in task_search:
		result.append(t["w"])
	task_search.close()
	return result

def write_keyword_space(d,hip):
	global task_search_list
	task_search_list.drop()
	items=d.items()     
	backitems=[[v[1],v[0]] for v in items] 
	backitems.sort(reverse = True) 
	pl = [InsertOne({"w":backitems[i][1],"c":backitems[i][0]}) for i in range(0,hip)]
	task_search_list.bulk_write(pl,ordered=True)

def write_internal_state(user_last_fileid):
	global user_internal
	user_internal.drop()
	l = []
	for i in user_last_fileid:
		l.append(InsertOne({"kw":i,"id":user_last_fileid[i]}))
	user_internal.bulk_write(l)

def read_internal_state():
	global user_internal
	result = {}
	inte = user_internal.find(no_cursor_timeout=True).batch_size(1000)
	for i in inte:
		result[i["kw"]]=i["id"]
	inte.close()
	return result

def write_cm_share_time(test_group):
	global CM_share_time
	filename = open("./Result/CmShare"+test_group,'w')
	for ke in CM_share_time:
		filename.writelines('len:\t'+str(ke) +'\t'+ str(np.mean(CM_share_time[ke]))+'\n')

	filename.close()

def Derive(Keywords_Cipher,fileid,k_id):
	global keywords_space, user_last_fileid,slice_of_cipher,Upload_Derive_Cipher_len,Upload_Derive_Cipher

	Derive_Cipher = []
	Derive_time = 0
	indexsize = 0
	for Keyword_Cipher in Keywords_Cipher:
		dur,keyword = LiuB_mod.AESDecrypt(k_id,Keyword_Cipher)
		#pdb.set_trace()
		if keyword not in keywords_space:
			keywords_space[keyword] = 1
		else:
			keywords_space[keyword] += 1
		Derive_time += dur
		if keyword not in user_last_fileid:
			last_fileid = ""
			last_slice = -1
		else :
			last_fileid,last_slice = user_last_fileid[keyword]

		dur , L ,I_w , R_w , C_w= LiuB_mod.Derive(keyword,fileid,last_fileid)
		#indexsize += sys.getsizeof(L)+sys.getsizeof(I_w)+sys.getsizeof(R_w)+sys.getsizeof(C_w)
		Derive_time += dur
		user_last_fileid[keyword] = [fileid,slice_of_cipher]
		Derive_Cipher.append(InsertOne({'L':L,'Iw':I_w,'Rw':R_w,'Cw':C_w,'LS':last_slice}))

		Upload_Derive_Cipher_len+=1
		Upload_Derive_Cipher.append(InsertOne({'L':L,'Iw':I_w,'Rw':R_w,'Cw':C_w,'LS':last_slice}))

		if Upload_Derive_Cipher_len % 1000000 == 0:
			t=threading.Thread(target=write_cipher_to_db,args=(mydb["user_ciphercol"+str(slice_of_cipher)],Upload_Derive_Cipher[:]))
			t.start()
			Upload_Derive_Cipher = []
			slice_of_cipher+=1



	return Derive_time, Derive_Cipher , indexsize

def write_slice_of_cipher(slice_of_cipher):
	global user_slice_of_cipher
	user_slice_of_cipher.drop()
	user_slice_of_cipher.insert_one({"num":slice_of_cipher})

def read_slice_of_cipher():
	global user_slice_of_cipher
	result = user_slice_of_cipher.find_one()
	return result["num"]

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
			return None

def thread_find(coll,L_id,i):
	return i,coll.find_one({'L':L_id})

def complex_thread_find(slice_of_cipher,L_W,last_slice):
		result = {}
		p = [MyThread(thread_find,(mydb["user_ciphercol"+str(i)],L_W,i)) for i in range(0,slice_of_cipher+1)]
		#pdb.set_trace()
		for t in p:
			t.start()
		for t in p:
			t.join()
		for t in p:
			hit,result = t.get_result()
			if result is not None:
				break
		return result
def write_cm_file_time(write_CM_share_cnt):
	global CM_share_time
	filename = open("./Result/CmShare"+test_db_name+str(write_CM_share_cnt),'w')
	for ke in CM_share_time:
		filename.writelines('len:\t'+str(ke) +'\t'+ str(np.mean(CM_share_time[ke]))+'\n')
	filename.close()
def write_cm_search_time(test_group,CM_search_time,CM_search_time_latency):
	filename = open("./Result/CmSearch"+test_db_name+str(test_group),'w')
	for ke in CM_search_time:
		filename.writelines('len:\t'+str(ke) +'\t'+ str(np.mean(CM_search_time[ke]))+'\t'+ str(np.mean(CM_search_time_latency[ke]))+ '\n')
	filename.close()

def Search_Phase():

	global user_ciphercol,user_last_fileid,myclient,time_with_matched_document
	search_result = []
	CM_search_time = dict()
	user_last_fileid = read_internal_state()
	slice_of_cipher = read_slice_of_cipher()
	task_search = read_keyword_space()
	print("load ok, ready")
	kc = 0
	for keyword in task_search[0:100]:
		Search_Phase_time = 0
		Search_Phase_time_latency = 0
		last_fileid,last_slice = user_last_fileid[keyword]
		if len(last_fileid) == 0:
			continue
		dur , L_T,J_T= LiuB_mod.UserKeyTrapdoor(keyword, last_fileid)

		Search_Phase_time+= dur

		cnt = 0

		while L_T[0]!=0 or L_T[1]!=0 or L_T[2]!=0 or L_T[3]!=0 or L_T[4]!=0:

			if cnt == 0:
				# simulate the once intereaction with Cloud B, all slices
				time_s = time.time()
				re = complex_thread_find(slice_of_cipher,L_T,last_slice)
				time_e = time.time()
				Search_Phase_time_latency = (time_e-time_s)
			else:
				hp = mydb["user_ciphercol"+str(last_slice)]
				re = hp.find_one({'L':L_T})
				#re = complex_thread_find(slice_of_cipher,L_T,last_slice)

			dur,iddata = LiuB_mod.AESDecrypt(J_T,re['Cw'])
			#re_id.append(iddata)
			dur,L_T ,J_T = LiuB_mod.XortoNext(J_T,re['Rw'],re['Iw'])
			last_slice = re["LS"]
			Search_Phase_time += dur
			cnt+=1
		kc+=1
		print("epoch",kc)
		if cnt not in CM_search_time:
			CM_search_time_latency[cnt] = []
			CM_search_time[cnt] = []
		CM_search_time_latency[cnt].append(Search_Phase_time_latency)
		CM_search_time[cnt].append(Search_Phase_time)

	write_cm_search_time(test_group,CM_search_time,CM_search_time_latency)
	print("success,wirte")

	 

def remove_local_inernal():
	global user_internal,user_slice_of_cipher,user_ciphercol
	global user_last_fileid,keywords_space,slice_of_cipher,heap_of_slice,Upload_Derive_Cipher_len,CM_share_time

	user_last_fileid = {}
	keywords_space = dict()
	slice_of_cipher = 0
	max_slice_of_cipher = 300
	Upload_Derive_Cipher_len = 0
	heap_of_slice = 1000000
	CM_share_time = dict()
	user_internal.drop()
	user_slice_of_cipher.drop()
	user_ciphercol.drop()

def write_cipher_to_db(ciphercol,data):
	#print(total_len)
	ciphercol.bulk_write(data,bypass_document_validation = False,ordered=False)


def cloud_manager_get_share_request(conn,messagedata):
	global fileid,k_id
	#pdb.set_trace()
	L_id, J_id, fileid, k_id = messagedata
	fileid = fileid.decode('ascii')

def cloud_manager_get_encrypt_request(conn,messagedata):
	global fileid,k_id,Upload_Derive_Cipher,Upload_Derive_Cipher_len,heap_of_slice,slice_of_cipher,CM_share_time
	Keywords_Cipher = messagedata
	Derive_time,Derive_Cipher,indexsize = Derive(Keywords_Cipher,fileid,k_id)

	if len(Derive_Cipher) not in CM_share_time:
		CM_share_time[len(Derive_Cipher)] = []
	CM_share_time[len(Derive_Cipher)].append(Derive_time)

def cloud_manager_get_search_request(conn,messagedata):
	global user_last_fileid,slice_of_cipher
	Search_Phase()
	print('search success')
	#send_data(conn,{'function':'search_ok','data':search_result})

def Test():
	global keywords_space, user_last_fileid,Upload_Derive_Cipher,slice_of_cipher
	if 's' in list(test_phase): # test search
		DB_Connect(test_db_name)
		Search_Phase()
	else :
		if 'b' in list(test_phase):
			DB_Setup(test_db_name)
		else:
			DB_Connect(test_db_name)

		sock = socket.socket()
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(("127.0.0.1", 18041))
		sock.listen(1024)
		print('socket success, waiting to test')
		write_CM_share_cnt = 0
	while 1:
		conn, addr = sock.accept()
		message = recv_data(conn)
		if message['function'] == 'send_file_key':
			#print('get share key')
			cloud_manager_get_share_request(conn,message['data'])
		if message['function'] == 'send_file_index':
			#print('get cipher ')
			cloud_manager_get_encrypt_request(conn,message['data'])
		if message['function'] == 'send_search_token':
			print('get search')
			write_cm_file_time(write_CM_share_cnt)
			if len(Upload_Derive_Cipher) > 0:
					t=threading.Thread(target=write_cipher_to_db,args=(mydb["user_ciphercol"+str(slice_of_cipher)],Upload_Derive_Cipher[:]))
					t.start()
					Upload_Derive_Cipher = []
			if 'w' in list(test_phase): # just write share data
				write_CM_share_cnt+=1
				write_keyword_space(keywords_space,2000)
				write_internal_state(user_last_fileid)
				write_slice_of_cipher(slice_of_cipher)
				remove_local_inernal()
			else:
				print('get search')
				write_keyword_space(keywords_space,2000)
				write_internal_state(user_last_fileid)
				write_slice_of_cipher(slice_of_cipher)
				cloud_manager_get_search_request(conn,message['data'])
		conn.close()

if __name__ == "__main__":
		test_db_name = str(sys.argv[1])
		test_phase = str(sys.argv[2])
		test_group = str (sys.argv[3])
		Test()

