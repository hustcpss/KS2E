#coding=utf-8
import Diana
import pdb

dur, ownerkey, keyleft, keyright = Diana.Setup() 
dur, ct1, ct2=Diana.Encrypt('hello' , 5 , '1')
dur, k2, kc, kdepth = Diana.Trapdoor('hello', 5)
dur, ctcheck = Diana.Search( 5, k2, kc, kdepth)

pdb.set_trace()
if ctcheck == ct1:
	print ('OK')

Diana.Continue(ownerkey, keyleft, keyright)

dur, ctcheck = Diana.Search( 5, k2, kc, kdepth)

if ctcheck == ct1:
	print ('OK')

