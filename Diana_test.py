#coding=utf-8
import Diana
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

keyword_counter = dict()

def DB_Setup(test_db_name):
	global myclient,mydb,datadb,task_search_list,ciphercol,internal,plaintextdb
	myclient = pymongo.MongoClient("mongodb://localhost:27017/?maxPoolSize=600&w=0")
	mydb = myclient["Diana"+test_db_name]
	plaintextdb = myclient[test_db_name] 
	ciphercol = mydb["ciphercol0"]
	internal = mydb["internal"]
	session_key = mydb["session_key"]
	task_search_list = mydb["task_search_list"]

	ciphercol.drop()
	internal.drop()
	session_key.drop()
	task_search_list.drop()

	ciphercol.ensure_index('ct1',unique=True)
	dur, ownerkey, keyleft, keyright = Diana.Setup()
	L = [InsertOne({"key":(ownerkey,keyleft,keyright)})]
	session_key.bulk_write(L)

def DB_Connect(test_db_name):
	global myclient,mydb,datadb,task_search_list,ciphercol,internal
	print('Testing on  ', test_db_name)
	myclient = pymongo.MongoClient("mongodb://localhost:27017/?maxPoolSize=600&w=0")
	mydb = myclient["Diana"+test_db_name]
	plaintextdb = myclient[test_db_name] 
	ciphercol = mydb["ciphercol0"]
	internal = mydb["internal"]
	session_key = mydb["session_key"]
	task_search_list = mydb["task_search_list"]

	re = session_key.find_one()
	ownerkey,keyleft,keyright = re["key"]
	Diana.Continue(ownerkey,keyleft,keyright)

def write_internal_state(Counter):
	global internal
	internal.drop()
	l = []
	for i in Counter:
		l.append(InsertOne({"kw":i,"id":Counter[i]}))
	internal.bulk_write(l)

def read_internal_state():
	global internal
	result = {}
	inte = internal.find(no_cursor_timeout=True).batch_size(1000)
	for i in inte:
		result[i["kw"]]=i["id"]
	inte.close()

	return result

def write_encrypted_time(test_group,data):
	filename = open("./Result/"+"DianaEnc"+test_db_name+str(test_group),'a')
	for d in data:
		filename.writelines(d)
	filename.close()

def Encrypt(keywords,fileid):

	encrypted_time = 0
	Keywords_Cipher = []
	for keyword in keywords:
		if keyword not in keyword_counter:
			keyword_counter[keyword] = 0

		dur, ct1, ct2=Diana.Encrypt(keyword , keyword_counter[keyword] , fileid)
		keyword_counter[keyword] +=1

		encrypted_time += dur
		Keywords_Cipher.append(InsertOne({'ct1':ct1,'ct2':ct2}))

	return encrypted_time , Keywords_Cipher

def write_cipher_to_db(ciphercol,data):

	ciphercol.bulk_write(data,bypass_document_validation = False,ordered=False)

def Ciphertext_Gen_Phase():
	global plaintextdb,ciphercol,mydb
	plaintext_col = plaintextdb["id_keywords_filter"]
	plaintext_cur = plaintext_col.find(no_cursor_timeout=True).batch_size(1000)

	total_encrypt_time = 0
	entry_counter = 0
	sector = 1000000
	result = []
	upload_list = []
	slice_of_data = 0
	for plaintext in plaintext_cur:

		encrypted_time , Keywords_Cipher = Encrypt(plaintext['kset'],plaintext['fid'])

		entry_counter += len(Keywords_Cipher)
		total_encrypt_time += encrypted_time
		if entry_counter >= sector:
			sector += 1000000
			slice_of_data += 1
			mydb["ciphercol"+str(slice_of_data)].ensure_index('ct1',unique=True)
			result.append('len:\t'+str(entry_counter) +'\t'+ str(total_encrypt_time)+'\n')
			if len(result) > 100:
				print('wirtedata')
				write_encrypted_time(test_group,result)
				result = []
		upload_list.extend(Keywords_Cipher)
		if len(upload_list)>= 200000:
			t=threading.Thread(target=write_cipher_to_db,args=(mydb["ciphercol"+str(slice_of_data)],upload_list[:]))
			t.start()
			upload_list = []

	if len(upload_list)> 0:
		t=threading.Thread(target=write_cipher_to_db,args=(mydb["ciphercol"+str(slice_of_data)],upload_list[:]))
		t.start()
		upload_list = []
	if len(result) > 0:
		write_encrypted_time(test_group,result)	

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

def thread_find(coll,ctcheck):
	re = coll.find_one({'ct1':ctcheck})
	return re

def complex_thread_find(coll_names,ctcheck):
		global mydb
		result = {}
		p =[MyThread(thread_find,(mydb[coll_names[i]],ctcheck)) for i in range(len(coll_names)) ]
		for t in p:
			t.start()
		for t in p:
			t.join()
		for t in p:
			result = t.get_result()
			if result is not None:
				break
		return result

def Search_Phase():

	global mydb,keyword_counter
	search_result = []
	Search_time = dict()
	latency = dict()
	keyword_counter = read_internal_state()
	task_search = read_keyword_space()
	coll_names = mydb.list_collection_names(session=None)
	temp = []
	for i in coll_names:
		if 'ciphercol' in i:
			temp.append(i)
	coll_names = temp
	print("load ok, ready")
	kc = 0
	Search_Phase_time = 0

	for keyword in task_search[0:30]:
		Search_Phase_time = 0
		if keyword not in keyword_counter:
			continue
		Conter = keyword_counter[keyword]
		#pdb.set_trace()
		dur, k2, kc, kdepth = Diana.Trapdoor(keyword, Conter-1)

		Search_Phase_time+= dur

		
		dur, ctcheck = Diana.Search( 0, k2, kc, kdepth)
		# simulate the once intereaction with Cloud Server
		time_s = time.time()
		re = complex_thread_find(coll_names,ctcheck)
		time_e = time.time()


		for i in range(Conter):
			dur, ctcheck = Diana.Search( i, k2, kc, kdepth)
			Search_Phase_time+= dur

		if Conter not in Search_time:
			Search_time[Conter] = []

		print('epoch')

		Search_time[Conter].append(Search_Phase_time)
		latency[Conter]= time_e-time_s

	write_search_time(test_group,latency,Search_time)
	print("success,wirte")

def write_search_time(test_group, latency, Search_time):
	filename = open("./Result/"+"DianaSrch"+test_db_name+str(test_group),'w')
	for ke in Search_time:
		filename.writelines('len:\t'+str(ke) +'\t'+ str(np.mean(Search_time[ke]))+'\t' + str((np.mean(Search_time[ke]))/ke)+ '\t' + str(latency[ke]) + '\n')
	filename.close()


def Test():
	l = list(test_phase)
	print ('*********************************************')
	print ('start test_group', test_group)
	if 'b' in l:
		print('start initial db')
		DB_Setup(test_db_name)
		Ciphertext_Gen_Phase()
		write_internal_state(keyword_counter)
		write_keyword_space(keyword_counter,2000)
	else:
		DB_Connect(test_db_name)

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

	