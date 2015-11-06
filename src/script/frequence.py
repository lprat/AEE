#!/usr/bin/env python
#FREQUENCE CREATE REFERENCE BASE
# POC on syslog event -- experimental version
#Lionel PRAT lionel.prat9@gmail.com
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

#TODO
#menu config
#if len(sys.argv) < 2:
#    print("Syntaxe: frequence.py file_config_freq")
#    sys.exit(0)

# get trace logger and set level
tracer = logging.getLogger('elasticsearch.trace')
tracer.setLevel(logging.INFO)
tracer.addHandler(logging.FileHandler('/tmp/es_trace.log'))
basecreate = False
es = Elasticsearch(["localhost"],timeout=240)
existano = es.indices.exists(index='frequence')
if existano:
  basecreate = False
  result = es.indices.delete(index='frequence')
else:
  basecreate = True

#recuperation d une semaine
now=datetime.now()
nd=datetime(int(now.strftime('%Y')),int(now.strftime('%m')),int(now.strftime('%d')))
dd=datetime(int(now.strftime('%Y')),int(now.strftime('%m')),int(now.strftime('%d')))+timedelta(days=-7)
und=nd.strftime("%s000")
udd=dd.strftime("%s000")

#creation de la requete selon le fichier
print udd
print und
filter_add = [{"range": { "@timestamp": {"from": udd, "to": und}}}, { "exists": { "field": "syslog_program"} }, { "exists": { "field": "@source_host"} }, { "exists": { "field": "syslog_pri"} },{ "exists": { "field": "status"} },{ "exists": { "field": "@timestamp"} }, {"term": {"tags": "normalized"}}]
aggr_add = {}
#parse file et add filter + agg
aggr_add["SOURCE"] = { "terms": { "field": "@source_host.raw", "size": 0, "order": {"_count": "desc"}}, "aggregations": { "SG": { "terms": { "field": "syslog_program.raw", "size": 0, "order": {"_count": "desc"}}, "aggregations": { "PRI": { "terms": { "field": "syslog_pri.raw", "size": 0, "order": {"_count": "desc"}},"aggregations": { "STATUS": { "terms": { "field": "status.raw", "size": 0, "order": {"_count": "desc"}},"aggregations": { "DATE": { "date_histogram" : {"field": "@timestamp", "interval": "1h", "format": "e-H"}  } }} }}}} }}

#aggr_add["DATE"] = { "date_histogram" : {"field": "@timestamp", "interval": "1h", "format": "e-k"}  }

result = es.search(
# index='_all', size=0, search_type='count', timeout=20,
#pose des problemes si on met l'option count & size, manque des resultats
  index='_all',
  body={
    "query": { "filtered": { "filter": { "bool": { "must": filter_add } } } }, "aggregations": aggr_add
  }
)

#[HOST][SG][PRI][STATUS][JOUR][HEURE][0][REPARTITION  _ACTIVE: BOOL TRUE FLASE]
#[HOST][SG][PRI][STATUS][JOUR][HEURE][1][POURCENTAGE D ERREUR %20]
#[HOST][SG][PRI][STATUS][JOUR][HEURE][2][REG MAX TOTAL %]
#[HOST][SG][PRI][STATUS][JOUR][HEURE][3][COUNT EN COURS %]
#print(json.dumps(result))
#print "\n\n\n"

#creation du json
#attention toute les heures ne sont pas defini, si c'est le cas == 0 (evite de surcharger la memoire pour rien)
tableau = {}
for hit in result['aggregations']['SOURCE']['buckets']:
  #tableau = {}
  #print("SOURCE == %s" % (hit['key']))
  tableau[str(hit['key'])]={}
  for hitx in hit['SG']['buckets']:
    #print("\tSG == %s" % (hitx['key']))
    tableau[str(hit['key'])][str(hitx['key'])]={}
    for hitz in hitx['PRI']['buckets']:
      #print("\t\tPRI == %s" % (hitz['key']))
      tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])]={}
      for hity in hitz['STATUS']['buckets']:
        #print("\t\t\tSTATUS == %s" % (hity['key']))
        tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])]={}
        for hitw in hity['DATE']['buckets']:
          jh=hitw['key_as_string'].split('-')
          if not str(jh[0]) in tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])].keys():
            tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])]={}
          if not str(jh[1]) in tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])].keys():
            tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]={}
          if not 'MAX' in tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])].keys():
            tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['MAX']=int(hitw['doc_count'])
          elif int(hitw['doc_count']) > tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['MAX']:
            tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['MAX']=int(hitw['doc_count'])
          if tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['MAX'] < 5:
            tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['POURC']=100
          else:
            tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['POURC']=20
          tableau[str(hit['key'])][str(hitx['key'])][str(hitz['key'])][str(hity['key'])][str(jh[0])][str(jh[1])]['REP']=0
es.index(index="frequence", doc_type='freq', body=tableau)
#print(json.dumps(tableau))
#ecriture du tableau dans ES
    #recuperation des pri par syslog_program
#calcule IP_REMOTE
#clean
es.indices.clear_cache()
