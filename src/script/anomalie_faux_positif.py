#!/usr/bin/env python
#Script apprentissage faux positifs
#Lionel PRAT -- lionel.prat9@gmail.com
#TODO 
#ne fonctionne pas encore!!!
#NOT WORK - DONT USE!
from __future__ import print_function
import time
import logging
from datetime import datetime, timedelta
from dateutil.parser import parse as parse_date
import pprint
import os
import json
import chardet
from subprocess import call
import sys
import re

pp = pprint.PrettyPrinter(indent=0)

from elasticsearch import Elasticsearch
if len(sys.argv) < 3:
    print("Syntaxe: anomalie_faux_positif.py file_contains_patterns id_event")
    sys.exit(0)
ifile = sys.argv[1]
id_change = sys.argv[2]
if len(sys.argv) == 4:
    imsg = sys.argv[3]
else:
    imsg = 100
imsg=int(imsg)
if len(sys.argv) == 5:
    iterms = sys.argv[4]
else:
    iterms = 100
iterms=int(iterms)
if len(sys.argv) == 6:
    iaggr = sys.argv[5]
else:
    iaggr = 15
iaggr=int(iaggr)
input = file(ifile)
if len(sys.argv) == 7:
    ipourc = sys.argv[6]
else:
    ipourc = 10
ipourc=int(ipourc)
lineno = 0
reg_list = {}
for line in input:
    words = line.split('=>>')
    lineno += 1
    if words:
        words[1] = words[1].replace("\n" , "")
        reg_list[words[0]] = words[1] 

# get trace logger and set level
tracer = logging.getLogger('elasticsearch.trace')
tracer.setLevel(logging.INFO)
tracer.addHandler(logging.FileHandler('/tmp/es_trace.log'))
# instantiate es client, connects to localhost:9200 by default
es = Elasticsearch(["localhost:9200"],timeout=120)
#TODO: 
#delete default
#resultg = es.indices.delete(index='anomalie')
#create default mapping
#es.indices.delete("anomalie")
#sys.exit(0)
basecreate = False
baseanook = {}
existano = es.indices.exists(index='anomalie')
if existano:
     baseano = es.search(index='anomalie', size=1000, doc_type='sig',q='*')
     for elemx in baseano['hits']['hits']:
         basesig = {}
         infocomp = {}
         basepri = {}
         for nkey,nval in elemx['_source'].items():
             if nkey != 'SG' and nkey != 'PRI' and nkey != 'SIGF':
                 infocomp[nkey] = nval
         infocomp['_id'] = elemx['_id']
         infocomp['_index'] = elemx['_index']
         infocomp['_type'] = elemx['_type']
         basesig[elemx['_source']['SIGF']] = infocomp
         basepri[elemx['_source']['PRI']] = basesig
         if elemx['_source']['SG'] not in baseanook.keys():
             baseanook[elemx['_source']['SG']] = basepri
         else:
             if elemx['_source']['PRI'] not in baseanook[elemx['_source']['SG']].keys():
                 baseanook[elemx['_source']['SG']][elemx['_source']['PRI']] = basesig
             else:
                 baseanook[elemx['_source']['SG']][elemx['_source']['PRI']][elemx['_source']['SIGF']] = infocomp
else:
    print("La base anomalie n'existe pas...")
    sys.exit(0)
query_sg=""
query_pri=""
sig_sg=""
sig_pri=""
query_msg=""
sig_field = {}
nd=datetime.now()
dd=datetime.now()+timedelta(hours=-1)
und=nd.strftime("%s000")
udd=dd.strftime("%s000")
#recuperation de tous les syslog_program existant
query_id='_id:("'+id_change+'")'
#recherche des champs/fields d'un message TYPE [SG/PRI/MESSAGE]
resultz = es.search(
    index='_all', size=1, timeout=120, doc_type='syslog',
    body={
        query": { "filtered": { "filter": { "bool": { "must": [ {"fquery": {"query": {"query_string": {"query": query_id} },"_cache": "false"}} ] } } } }
    }
)
es.indices.clear_cache()
sav_field = []
sav_field2 = {}
for hitz in resultz['hits']['hits']:
    query_pri='syslog_pri:("'+hitz['_source']['syslog_pri'].encode('utf-8')+'")'
    query_sg='syslog_program:("'+hitz['_source']['syslog_program'].encode('utf-8')+'")'
    sig_sg=hitz['_source']['syslog_program']
    sig_pri=hitz['_source']['syslog_pri']
    msg_re=hitz['_source']['@message'].replace('"','\\"')
    query_msg='@message:("'+msg_re+'")'
    for key, value in hitz['_source'].items():
        #elimination des champs generiques
        if str(key) == "tags" or str(key) == "@source_host" or str(key) == "_type" or str(key) == "type" or str(key) == "@timestamp" or str(key) == "@message" or str(key) == "@version" or str(key) == "_id" or str(key) == "_index" or str(key) == "_type" or str(key) == "host" or str(key) == "message" or str(key) == "received_at" or str(key) == "received_from" or str(key) == "syslog_facility" or str(key) == "syslog_facility_code" or str(key) == "syslog_pri" or str(key) == "syslog_pid" or str(key) == "syslog_program" or str(key) == "syslog_severity_code" or str(key) == "syslog_severity" or str(key) == "timestamp" or str(key) == "risk_note" or str(key) == "risk_desc" or str(key) == "risk_relation_note" or str(key) == "SIG-TERMS":
            continue
        sav_field.append(str(key))
        sav_field2[str(key)] = value
if len(sav_field) > 1:
    # creation de la signature simple pour eviter muti recherche: field + nombre de fois ou il match
    #SIG string: FIELD{||||}
    sav_field.sort()
    str_field = '|'.join(sav_field)
    if str_field not in sig_field.keys():
        sig_field[str_field] = query_msg + " PRI:" + query_pri + " SG:" + query_sg
sigadd = {}
for key,value in sig_field.items():
#QUE MET ON A JOUR:
# - LEN MIN & MAX- LIMIT - REGEXP
    print("SG == %s = %s" % (hit['key'],hit['doc_count']))
    print("PRI == %s = %s" % (hitx['key'],hitx['doc_count']))
    print("SIGNATURE: %s  == %s" % (key,value))
    #verification existance
    if not basecreate:
        if sig_sg in baseanook.keys():
            if sig_pri in baseanook[sig_sg].keys():
                if key in baseanook[sig_sg][sig_pri].keys():
                #mise a jour relation
                    field_list = key.split("|")
                    #verifier LEN MIN & MAX- LIMIT - REGEXP pour chaque field
                    for elemx in field_list:
                         #int ou string?
                         resultg = es.indices.get_field_mapping(index='_all', field=elemx)
                         if baseanook[sig_sg][sig_pri][key]['FIELD_UNIQ_'+elemx] == 0
                             #uniq - verif limit
                             if str(sav_field2[elemx]) not in baseanook[sig_sg][sig_pri][key]['FIELD_LIMIT_'+elemx]:
                                 #ajouter a la liste
                                 list_tmp = baseanook[sig_sg][sig_pri][key]['FIELD_LIMIT_'+elemx]
                                 list_tmp.append(str(sav_field2[elemx]))
                                 #changer le champs dans l'enregistrement
                                 nfield='FIELD_LIMIT_'+elemx
                                 resultwst = es.update(index=baseanook[sig_sg][sig_pri][key]['_index'], doc_type=baseanook[sig_sg][sig_pri][key]['_type'] , id=baseanook[sig_sg][sig_pri][key][key]['_id'], body = { "doc": { nfield: list_tmp}} ) 
                         if 'FIELD_LEN_MIN_'+elemx in baseanook[sig_sg][sig_pri][key].keys():
                              lenvalue=len(str(sav_field2[elemx]))
                              if lenvalue < baseanook[sig_sg][sig_pri][key]['FIELD_LEN_MIN_'+elemx]:
                                  #changer le champs dans l'enregistrement
                                  nfield='FIELD_LEN_MIN_'+elemx
                                  resultwst = es.update(index=baseanook[sig_sg][sig_pri][key]['_index'], doc_type=baseanook[sig_sg][sig_pri][key]['_type'] , id=baseanook[sig_sg][sig_pri][key][key]['_id'], body = { "doc": { nfield: lenvalue}} )
                         if 'FIELD_LEN_MAX_'+elemx in baseanook[sig_sg][sig_pri][key].keys():
                              lenvalue=len(str(sav_field2[elemx]))
                              if lenvalue > baseanook[sig_sg][sig_pri][key]['FIELD_LEN_MAX_'+elemx]:
                                  #changer le champs dans l'enregistrement
                                  nfield='FIELD_LEN_MAX_'+elemx
                                  resultwst = es.update(index=baseanook[sig_sg][sig_pri][key]['_index'], doc_type=baseanook[sig_sg][sig_pri][key]['_type'] , id=baseanook[sig_sg][sig_pri][key][key]['_id'], body = { "doc": { nfield: lenvalue}} )
                         if 'FIELD_REGEX_'+elemx in baseanook[sig_sg][sig_pri][key].keys():
                             match_name = []
                             for keyz,valuez in reg_list.items():    
                                  match = None
                                  match = re.search(str(valuez), str(hitw['key']))
                                  if match:
                                      match_name.append(keyz)
                             match_name.sort()
                             regsig = '::'.join(match_name)
                             if regsig not in baseanook[sig_sg][sig_pri][key]['FIELD_REGEX_'+elemx]:
                                 #ajouter a la liste
                                 list_tmp = baseanook[sig_sg][sig_pri][key]['FIELD_REGEX_'+elemx]
                                 list_tmp.append(regsig)
                                 #changer le champs dans l'enregistrement
                                 nfield='FIELD_REGEX_'+elemx
                                 resultwst = es.update(index=baseanook[sig_sg][sig_pri][key]['_index'], doc_type=baseanook[sig_sg][sig_pri][key]['_type'] , id=baseanook[sig_sg][sig_pri][key][key]['_id'], body = { "doc": { nfield: list_tmp}} ) 
                else
                #la sig n existe pas il faut la creer
                
