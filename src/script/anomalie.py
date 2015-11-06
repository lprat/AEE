#!/usr/bin/env python
#ANALYSE LEX/SYN/SEM/REL -> CREATE REFERENCE BASE
# POC on syslog event -- experimental version
#Lionel PRAT lionel.prat9@gmail.com
#SI sig deja presente, verification des RELATION, si nouvelle ajouter
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

#menu
from elasticsearch import Elasticsearch
if len(sys.argv) < 2:
    print("Syntaxe: anomalie.py file_contains_patterns [count_msg: default 100] [count_terms:default 100] [aggregation_terms_solo:default 15] [1% count:default 10]")
    sys.exit(0)
ifile = sys.argv[1]
if len(sys.argv) == 3:
    imsg = sys.argv[2]
else:
    imsg = 100
imsg=int(imsg)
if len(sys.argv) == 4:
    iterms = sys.argv[3]
else:
    iterms = 100
iterms=int(iterms)
if len(sys.argv) == 5:
    iaggr = sys.argv[4]
else:
    iaggr = 15
iaggr=int(iaggr)
input = file(ifile)
if len(sys.argv) == 6:
    ipourc = sys.argv[5]
else:
    ipourc = 10
ipourc=int(ipourc)
#initialisation regexp
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

##if you want delete base reference , uncomment line:
#es.indices.delete("anomalie")
#sys.exit(0)

#create base OR initializ base
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
    basecreate = True
    es.indices.create('anomalie', ignore=400, body= {'mappings': {'_default_': { 'dynamic_templates':[ { 'disable_string_analyzing': { 'match': '*','match_mapping_type': 'string', 'mapping': {'type': 'string', 'index': 'not_analyzed'} } }, { 'detect_integer': { 'match': '*_count', 'mapping': {'type': 'integer' } } } ] }} } )
    #bug es: mapping field different double et defois string...
    es.indices.put_mapping(index='_all',ignore_conflicts='true',doc_type='syslog',body={'syslog': { 'properties': {'proxyftp_read_sec': {'type': 'string', 'index': 'not_analyzed'}, 'proxyftp_read_bytes': {'type': 'string', 'index': 'not_analyzed'}}}} )

#choice range time for analyse event (depend of number events and date where eventz is clean
#ADJUST for you context!!!!! 
nd=datetime.now()
dd=datetime.now()+timedelta(hours=-1)
und=nd.strftime("%s000")
udd=dd.strftime("%s000")

#recuperation de tous les syslog_program existant avec filtre sur evenement normalise
result = es.search(
    index='_all', size=0, search_type='count',
    body={
"query": { "filtered": { "filter": { "bool": { "must": [ { "exists":{ "field": "syslog_program" } } , {"term": {"tags": "normalized"}}] } } } }, "aggregations": { "SP": { "terms": { "field": "syslog_program.raw", "size": 0, "order": {"_count": "desc"}}} }
    }
)
es.indices.clear_cache()

#recuperation PRI pour chaque SG different
for hit in result['aggregations']['SP']['buckets']:
    #print("SG == %s = %s" % (hit['key'],hit['doc_count']))
    #recuperation des pri par syslog_program
    query_sg='syslog_program:("'+hit['key'].encode('utf-8')+'")'
    resultx = es.search(
        index='_all', size=0, search_type='count',
        body={
        "query": { "filtered": { "filter": { "bool": { "must": [ {"fquery": {"query": {"query_string": {"query": query_sg} },"_cache": "false"}}, { "exists":{ "field": "syslog_program" } }, { "exists": { "field": "syslog_pri" } } ] } } } }, "aggregations": { "PRI": { "terms": { "field": "syslog_pri.raw", "size": 0, "order": {"_count": "desc"} }} }
        }
    )
    es.indices.clear_cache()

    #recuperation champs MESSAGE pour (SG|PRI)
    for hitx in resultx['aggregations']['PRI']['buckets']:
        #print("PRI == %s = %s" % (hitx['key'],hitx['doc_count']))
        #recuperation des messages par syslog_program & pri
        sig_field = {}
        query_pri='syslog_pri:("'+hitx['key'].encode('utf-8')+'")'
        resulty = es.search(
            index='_all', size=0, search_type='count', timeout=240,
            body={
            "query": { "filtered": { "filter": { "bool": { "must": [ {"fquery": {"query": {"query_string": {"query": query_sg} },"_cache": "false"}}, {"fquery": {"query": {"query_string": {"query": query_pri} },"_cache": "false"}}, { "exists":{ "field": "syslog_program" } }, { "exists":{ "field": "@message" } }, { "exists": { "field": "syslog_pri" } } ] } } } }, "aggregations": { "MSG": { "terms": { "field": "@message.raw", "size": imsg , "order": {"_count": "desc"}}} }
            }
        )
        es.indices.clear_cache()
        #recuperation des noms des champs pour chaque SG|PRI|MESSAGE differents
        for hity in resulty['aggregations']['MSG']['buckets']:
            #print("%s = %s" % (hity['key'],hity['doc_count']))
            msg_re=hity['key'].replace('"','\\"')
            query_msg='@message:("'+msg_re+'")'
            #recherche des champs/fields d'un message TYPE [SG/PRI/MESSAGE]
            resultz = es.search(
                index='_all', size=1, timeout=120,
                body={
                "query": { "filtered": { "filter": { "bool": { "must": [ {"fquery": {"query": {"query_string": {"query": query_sg} },"_cache": "false"}}, {"fquery": {"query": {"query_string": {"query": query_pri} },"_cache": "false"}}, {"fquery": {"query": {"query_string": {"query": query_msg} },"_cache": "false"}}, { "exists":{ "field": "syslog_program" } }, { "exists":{ "field": "@message" } }, { "exists": { "field": "syslog_pri" } } ] } } } }
               }
            )
            #tri des champs disponibles
            sav_field = []
            for hitz in resultz['hits']['hits']:
                for key, value in hitz['_source'].items():
                    #elimination des champs generiques
                    #TODO rajouter dans le menu l'option par fichier pour enlever les champs afin d'avoir les éléments identiques entre le filtre logstash et ici
                    if str(key) == "tags" or str(key) == "@source_host" or str(key) == "_type" or str(key) == "type" or str(key) == "@timestamp" or str(key) == "@message" or str(key) == "@version" or str(key) == "_id" or str(key) == "_index" or str(key) == "_type" or str(key) == "host" or str(key) == "message" or str(key) == "received_at" or str(key) == "received_from" or str(key) == "syslog_facility" or str(key) == "syslog_facility_code" or str(key) == "syslog_pri" or str(key) == "syslog_pid" or str(key) == "syslog_program" or str(key) == "syslog_severity_code" or str(key) == "syslog_severity" or str(key) == "timestamp" or str(key) == "risk_note" or str(key) == "risk_desc" or str(key) == "risk_relation_note" or str(key) == "SIG-TERMS":
                        continue
                    sav_field.append(str(key))
                    #print("%s = %s" % (hit['key'],hit['doc_count']))
            # >1 car @source_host ne compte pas mais est utile pour les relations directes
            if len(sav_field) > 1:
                # creation de la signature simple pour eviter muti recherche: field + nombre de fois ou il match
                #SIG string: FIELD{||||}
                sav_field.sort()
                str_field = '|'.join(sav_field)
                if str_field not in sig_field.keys():
                    sig_field[str_field] = query_msg + " PRI:" + query_pri + " SG:" + query_sg
                #else:
                    #sig_field[str_field] = sig_field[str_field] + 1
        # creation de la regexp par champs (fichier de l'option du menu contenant toutes les regexp a tester dans l'ordre du plus restreint au plus large)
        es.indices.clear_cache()
        sigadd = {}
        for key,value in sig_field.items():
            print("SG == %s = %s" % (hit['key'],hit['doc_count']))
            print("PRI == %s = %s" % (hitx['key'],hitx['doc_count']))
            print("SIGNATURE: %s  == %s" % (key,value))
            #verification existance
            if not basecreate:
                if hit['key'] in baseanook.keys():
                    if hitx['key'] in baseanook[hit['key']].keys():
                        if key in baseanook[hit['key']][hitx['key']].keys():
                            #mise a jour relation
                            print("Mise a jour RELATION")
                            comprelation = ipourc
                            if (baseanook[hit['key']][hitx['key']][key]['SIG_CNT']*0.01) < ipourc:
                                comprelation = 1
                                if not (baseanook[hit['key']][hitx['key']][key]['SIG_CNT']*0.01) > 1:
                                    comprelation = 0
                            find_exists = [ {"fquery": {"query": {"query_string": {"query": query_sg} },"_cache": "false"}}, {"fquery": {"query": {"query_string": {"query": query_pri} },"_cache": "false"}}, { "exists":{ "field": "syslog_program" } }, { "term": { "risk_note": 0 } }, { "exists": { "field": "syslog_pri" } } ]
                            field_list = key.split("|")
                            for elemx in field_list:
                                avdict = { "exists": { "field": elemx} }
                                find_exists.append(avdict)
                            resultw = es.search(index='_all', size=0, search_type='count', timeout=120,
                                      body={ "query": { "filtered": { "filter": { "bool": { "must": find_exists } } } }, "aggs": { "AGST": { "terms": { "field": "SIG-TERMS.raw", "size": 0, "order": {"_count": "desc"}, "min_doc_count": comprelation}}}}
                                      )
                            es.indices.clear_cache()
                            stlist = []
                            for hitw in resultw['aggregations']['AGST']['buckets']:
                                stlist.append(hitw['key'])
                            resultwst = es.update(index=baseanook[hit['key']][hitx['key']][key]['_index'], doc_type=baseanook[hit['key']][hitx['key']][key]['_type'] , id=baseanook[hit['key']][hitx['key']][key]['_id'], body = { "doc": { "SIG-TERMS": stlist}} )  
                            continue
            sigadd['SG'] = hit['key'].encode('utf-8')
            sigadd['PRI'] = hitx['key'].encode('utf-8')
            sigadd['SIGF'] = key.encode('utf-8')
            field_list = key.split("|")
            field_listx = key.split("|")
            field_listx.append("source_host")
            #test relation entre terms
            cnt_ter = 0
            total_ter = len(field_listx)
            find_aggr = {}
            find_exists = [ {"fquery": {"query": {"query_string": {"query": query_sg} },"_cache": "false"}}, {"fquery": {"query": {"query_string": {"query": query_pri} },"_cache": "false"}}, { "exists":{ "field": "syslog_program" } }, { "exists": { "field": "syslog_pri" } } ]
            for elemx in field_list:
                avdict = { "exists": { "field": elemx} }
                find_exists.append(avdict)
                resultg = es.indices.get_field_mapping(index='_all', field=elemx)
                if "u'type': u'integer'" in str(resultg) or "u'type': u'long'" in str(resultg):
                    namex = elemx
                    fieldx = "AGGR_"+elemx
                    fieldx2 = "CARD_"+elemx
                    fieldx0 = "STATS_"+elemx
                    find_aggr[fieldx0] = { "stats": { "field": namex }}
                    find_aggr[fieldx] = { "terms": { "field": namex, "size": iaggr+1, "order": {"_count": "desc"}}}
                    find_aggr[fieldx2] = {"cardinality":{"field": namex, "precision_threshold": 10000}}
                else:
                    namex = elemx
                    if "u'type': u'string'" in str(resultg):
                        namex = elemx+".raw"
                    fieldx = "AGGR_"+elemx
                    fieldx2 = "CARD_"+elemx
                    find_aggr[fieldx] = { "terms": { "field": namex, "size": iterms, "order": {"_count": "desc"}}}
                    find_aggr[fieldx2] = {"cardinality":{"field": namex, "precision_threshold": 10000}}
            print(find_exists)              
            print(find_aggr)  
            resultw = es.search(
                index='_all', size=0, search_type='count', timeout=120,
                body={
                "query": { "filtered": { "filter": { "bool": { "must": find_exists } } } }, "aggs": find_aggr
                }
            )
            es.indices.clear_cache()
            total_f=int(resultw['hits']['total'])
            sigadd['SIG_CNT'] = total_f
            for elemx in field_list:
                resultg = es.indices.get_field_mapping(index='_all', field=elemx)
                #if "u'type': u'string'" not in str(resultg):
                if "u'type': u'integer'" in str(resultg) or "u'type': u'long'" in str(resultg):
                    sigadd['FIELD_TYPE_'+elemx] = 'int'
                    fieldx = "AGGR_"+elemx
                    fieldx2 = "CARD_"+elemx
                    fieldx0 = "STATS_"+elemx
                    total_t=int(resultw['aggregations'][fieldx2]['value'])  
                    print("Total hit [TERM INT %s]: %d pour Cardinality terms: %d" % (elemx,total_f, total_t ))
                    if total_t < iaggr:
                        term_list = []
                        for hitw in resultw['aggregations'][fieldx]['buckets']:
                            print("\t\t TERM-15: %s" % str(hitw['key']))
                            term_list.append(str(hitw['key']))
                        sigadd['FIELD_UNIQ_'+elemx] = 0 
                        sigadd['FIELD_LIMIT_'+elemx] = term_list
                    elif (total_t > 1) and (total_t<(total_f*0.01)):
                        print("\tTERM >1 et moins d'un pourcent du total")
                        sigadd['FIELD_UNIQ_'+elemx] = 1 
                    else:
                        sigadd['FIELD_UNIQ_'+elemx] = 2
                    print ( "\tTERM STATS Count: %d mini: %s max: %s avg: %s sum: %s" % (resultw['aggregations'][fieldx0]['count'],str(resultw['aggregations'][fieldx0]['min']),str(resultw['aggregations'][fieldx0]['max']),str(resultw['aggregations'][fieldx0]['avg']),str(resultw['aggregations'][fieldx0]['sum'])))
                    sigadd['FIELD_STATS_CNT_'+elemx] = resultw['aggregations'][fieldx0]['count']
                    sigadd['FIELD_STATS_MAX_'+elemx] = resultw['aggregations'][fieldx0]['max']
                    sigadd['FIELD_STATS_MIN_'+elemx] = resultw['aggregations'][fieldx0]['min']
                    sigadd['FIELD_STATS_AVG_'+elemx] = resultw['aggregations'][fieldx0]['avg']
                    sigadd['FIELD_STATS_SUM_'+elemx] = resultw['aggregations'][fieldx0]['sum']
                else:
                    if "u'type': u'string'" in str(resultg):
                        sigadd['FIELD_TYPE_'+elemx] = 'string'
                    else:
                        sigadd['FIELD_TYPE_'+elemx] = 'another'
                    fieldx = "AGGR_"+elemx
                    fieldx2 = "CARD_"+elemx
                    # recuperation du type de champs customs puis aggregations ou stats selon type
                    #find_exists_ok = find_exists[0:-1]
                    total_t=int(resultw['aggregations'][fieldx2]['value'])
                    moyen_max=0
                    moyen_moy=0
                    moyen_min=10000000
                    n_pair=0
                    n_impair=0
                    match_all_name= {}
                    match_all_name_l= []
                    sav_ten_terms = []
                    count_aggr = 0
                    term_faible = 0
                    if (total_t > 1) and (total_t<(total_f*0.01)):
                        term_faible = 1
                    type_encoding_cnt = {}
                    #hits":{"total":1833 / nombre d'aggregation si total 1%
                    for hitw in resultw['aggregations'][fieldx]['buckets']:
                        #print("TERM %s: %s = %s" % (field_select,hitw['key'],hitw['doc_count']))
                        count_aggr = count_aggr + 1
                        if isinstance(hitw['key'], unicode):
                            hitw['key']=hitw['key'].encode('utf-8')
                        if count_aggr < iaggr+1:
                            #print("PX: %s"%(hitw['key']))
                            sav_ten_terms.append(str(hitw['key']))
                        tmp_size=len(str(hitw['key']))
                        moyen_moy=moyen_moy+tmp_size
                        if (tmp_size % 2 == 0):
                            n_pair=1
                        else:
                            n_impair=1
                        if tmp_size>moyen_max:
                            moyen_max=tmp_size
                        if moyen_min>tmp_size:
                            moyen_min=tmp_size
                        #detect type encodage 
                        tmp_encode= chardet.detect(str(hitw['key']))
                        type_encoding = tmp_encode['encoding']
                        type_encoding_cnt[str(type_encoding)] = 1
                        #pattern matching
                        match_name = []
                        for keyz,valuez in reg_list.items():
                            match = None
                            match = re.search(str(valuez), str(hitw['key']))
                            if match:
                                match_name.append(keyz)
                        match_name.sort()
                        match_all_name_l.append(match_name)
                        if '::'.join(match_name) not in match_all_name.keys():
                            match_all_name['::'.join(match_name)] = 1
                        else:
                            match_all_name['::'.join(match_name)] = match_all_name['::'.join(match_name)]+1
                    print("Total hit [TERM %s]: %d pour %d terms [Cardinality terms: %d]" % (elemx,total_f,  count_aggr,total_t ))                   
                    if count_aggr == 0:
                        print("ERREUR TERMS == 0 !!!")
                        sys.exit(0)
                    if count_aggr < iaggr:
                        count_term = 1
                        sigadd['FIELD_UNIQ_'+elemx] = 0 
                        sigadd['FIELD_LIMIT_'+elemx] = sav_ten_terms
                        for elemd in sav_ten_terms:
                             print("\tTerms %d => %s"%(count_term,elemd))
                             count_term = count_term + 1
                    elif term_faible == 1:
                        print("\tTERM >1 et moins d'un pourcent du total") 
                        sigadd['FIELD_UNIQ_'+elemx] = 1 
                    else:
                        sigadd['FIELD_UNIQ_'+elemx] = 2
                    encode_list= []
                    for tkey, tvalue in type_encoding_cnt.items():
                        print( "\tEncoding type: %s" % (tkey))
                        encode_list.append(str(tkey))
                    sigadd['FIELD_ENCODE_'+elemx] = encode_list
                    print("\tTerms len max: %d , min: %d, avg: %d" % (moyen_max,moyen_min,moyen_moy / count_aggr))
                    print("\tTerms len pair: %d , impair: %d\n\tListe regexp commun:" % (n_pair,n_impair))
                    if n_pair == 1 and n_impair == 0:
                        sigadd['FIELD_PI_'+elemx] = 0
                    elif n_pair == 0 and n_impair == 1:
                        sigadd['FIELD_PI_'+elemx] = 1
                    elif n_pair == 1 and n_impair == 1:
                        sigadd['FIELD_PI_'+elemx] = 2
                    sigadd['FIELD_LEN_MIN_'+elemx] = moyen_min
                    sigadd['FIELD_LEN_MAX_'+elemx] = moyen_max
                    sigadd['FIELD_LEN_AVG_'+elemx] = moyen_moy / count_aggr
                    if match_all_name_l:
                        regexp_commun = set(match_all_name_l[0])
                        for selm in match_all_name_l[1:]:
                            regexp_commun.intersection_update(selm)
                        print(regexp_commun)
                        sigadd['FIELD_REGEX_MIN_'+elemx] = list(regexp_commun)
                    else:
                        print("\tNo regexp commun")
                        sigadd['FIELD_REGEX_MIN_'+elemx] = [] 
                    fregexp = []
                    for keyd, valued in match_all_name.items():
                        print("\tREGEXP %s total match: %d" % (keyd, valued))
                        fregexp.append(keyd)
                    sigadd['FIELD_REGEX_'+elemx] = fregexp
            #add sig
            es.index(index="anomalie", doc_type='sig', body=sigadd)
#           else:
                #TODO si pas de champs custom, pas de regle de parsing en cours pour ce type de message: informer l'utilisateur des champs non analyse
                #creation fichier de log - NOT ANALYZED
#print(json.dumps(result))
