# encoding: utf-8
# Filter "anomalie" analyze behavior lexical/syntaxic/semantic/relational
# POC on syslog event -- experimental version
# Contact: Lionel PRAT (lionel.prat9@gmail.com)
require "logstash/filters/base"
require "logstash/namespace"

#TODO: note of risk must be optimized

class LogStash::Filters::Anomalie < LogStash::Filters::Base
  config_name "anomalie"
  milestone 1

  #ES HOST
  config :hosts, :validate => :array
  # Elasticsearch index name -- BASE REF SIG
  config :idx_name, :validate => :string, :default => "anomalie"
  # Elasticsearch type name -- BASE REF SIG
  config :type_name, :validate => :string, :default => "sig"
  #RegExp DB FILE -> exemple: /etc/logstash/pattern.db
  config :dbfile, :validate => :string
  #pivot 1 syslog_programm 
  config :sg_extract, :validate => :string, :default => "syslog_program"
  #pivot 2 syslog_pri
  config :spri_extract, :validate => :string, :default => "syslog_pri"
  #exclude field for create sig
  config :exclude_create_sig, :validate => :array, :default => ["tags","@source_host","_type","type","@timestamp","@message","@version","_id","_index","_type","host","message","received_at","received_from","syslog_facility","syslog_facility_code","syslog_pri","syslog_pid","syslog_program","syslog_severity_code","syslog_severity"]


  public
  def register
    require "elasticsearch"
    @logger.info("Anomalie Base in ElasticSearch Load...", :hosts => @hosts)
    @client = Elasticsearch::Client.new hosts: @hosts
    baseano = @client.search index: idx_name, type: type_name, q: '*', size: 0
    @baseanook = {}
    @regexpdb = {}
    unless baseano.nil?
      @logger.info(".")
      unless baseano['hits'].nil?
        @logger.info(".")
        unless baseano['hits']['hits'].nil?
          @logger.info("Anomalie base loaded!")
          baseano['hits']['hits'].each do |elemx|
            elemx['_source'].each do |nkey,nval|
              if nkey != 'SG' and nkey != 'PRI' and nkey != 'SIGF' 
                infocomp[nkey] = nval 
              end
            end
            basesig[elemx['_source']['SIGF']] = infocomp
            basepri[elemx['_source']['PRI']] = basesig
            @baseanook[elemx['_source']['SG']] = basepri
          end
          File.readlines(@dbfile).each do |line|
            elem1, elem2 = line.split(/=>>/)
            elem2.delete!("\n")
            @regexpdb[elem1] = elem2
          end
        else
          @logger.error("Error for load anomalie base...")
        end
      else
        @logger.error("Error for load anomalie base...")
      end
    else
      @logger.error("Error for load anomalie base...")
    end 
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    unless event[@sg_extract].nil?
      unless event[@spri_extract].nil?
        unless @baseanook[event[@sg_extract]].nil?
          unless @baseanook[event[@sg_extract]][event[@spri_extract]].nil?
            sigf = String.new
            event.to_hash.each do |name, value|
            if not @exclude_create_sig.include? name
                if sigf.empty?
                  sigf = name
                else
                  sigf = sigf + "|" + name
                end
              end
              if sigf.empty?
                # rien a faire
                #pas de normalisation mise en place
              else
                rnote=0
                rdesc = []
                #field 1 pourcent
                field1p = []
                reqfield = []
                unless @baseanook[event[@sg_extract]][event[@spri_extract]][sigf].nil?
                  #verification des fields
                  event.to_hash.each do |name, value|
                    if not @exclude_create_sig.include? name
                      sname="FIELD_TYPE_"+name
                      if @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] == "int"
                        #int
                        if not value.is_a? Integer
                          rnote=rnote+1
                          rdesc << "Value of field:"+name+ " is not numeric."
                        end
                        #verif term list
                        #verif max & min  & avg+min/2 & avg+max/2
                      else
                        #string
                        verifyvar=0
                        if not value.is_a? String
                          rnote=rnote+1
                          rdesc << "Value of field:" +name+ " is not string."
                        end
                        sname="FIELD_UNIQ_"+name
                        if @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] == 0
                          # verif in list FIELD_LIMIT_
                          reqfield << name
                          lsname="FIELD_LIMIT_"+name
                          if not @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname].include? value
                            rnote=rnote+2
                            rdesc << "Value of field:" +name+ " not contains defined list."
                          else
                            verifyvar=1
                          end
                        elsif @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] == 1
                          # element to verify with requet elasticsearch relation
                          field1p << name
                          reqfield << name
                        end
                        if verifyvar == 0
                          lenvalue=value.length
                          sname="FIELD_ENCODE_"+name
                          if not value.valid_encoding? and @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] == "ascii"
                            rnote=rnote+1
                            rdesc << "Value of field:"+name+ " is not ascii."
                          end
                          sname="FIELD_PI_"+name
                          if @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] != 2
                            if lenvalue%2==0
                              if @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] == 1
                                rnote=rnote+1
                                rdesc << "Value of field:"+name+ " is not length pair."
                              end
                            else
                              if @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname] == 0
                                rnote=rnote+1
                                rdesc << "Value of field:"+name+ " is not length impair."
                              end
                            end
                            #verifier pair ou impair
                          end
                          minname="FIELD_LEN_MIN_"+name
                          maxname="FIELD_LEN_MAX_"+name
                          avgname="FIELD_LEN_AVG_"+name
                          if @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][minname] >= lenvalue and lenvalue <= @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][maxname]
                            #verification length
                            if ((@baseanook[event[@sg_extract]][event[@spri_extract]][sigf][minname]+@baseanook[event[@sg_extract]][event[@spri_extract]][sigf][avgname])/2) >= lenvalue and lenvalue <= ((@baseanook[event[@sg_extract]][event[@spri_extract]][sigf][maxname]+@baseanook[event[@sg_extract]][event[@spri_extract]][sigf][avgname])/2)
                              #good
                            else
                              rnote=rnote+1
                              rdesc << "Value of field:"+name+ " is bad length."
                            end
                          else
                            #bad
                            rnote=rnote+2
                            rdesc << "Value of field:"+name+ " is bad length limit."
                          end
                          #verif regexp
                          rlist = []
                          @regexpdb.each do |key, value|
                            match = Regexp.new(value, nil, 'n').match(string)
                            if not match.nil?
                              rlist << key
                            end
                          end
                          sname="FIELD_REGEX_MIN_"+name
                          @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname].each do |elm|
                            if not rlist.include? elm
                              rnote=rnote+1
                              rdesc << "Value of field:"+name+ " is not match regexp min: #{elm}."
                            end
                          end
                          sname="FIELD_REGEX_"+name
                          srlist=rlist.join("::")
                          if not @baseanook[event[@sg_extract]][event[@spri_extract]][sigf][sname].include? srlist
                            rnote=rnote+2
                            rdesc << "Value of field:"+name+ " is not match regexp list: #{srlist}."
                          end
                          #query relation search_type=count&query_cache=false&size=0&timeout=60
                          if not reqfield.empty?
                            #10: faible + sauf si 1% total hit < 10 alors prendre 1, si 1% total hit > 1
                            comprelation = 10
                            if (@baseanook[event[@sg_extract]][event[@spri_extract]][sigf]['SIG_CNT']*0.01) < 10
                              comprelation = 1
                              if not (@baseanook[event[@sg_extract]][event[@spri_extract]][sigf]['SIG_CNT']*0.01) > 1
                                comprelation = 0
                              end
                            end 
                            reqfield << "@source_host"
                            qsg = "syslog_program:(\""+event[@sg_extract]+"\")"
                            qpri = "syslog_pri:(\""+event[@spri_extract]+"\")"
                            filter = [{"fquery": {"_cache": "false","query": {"query_string": {"query": qsg}}}}, { "fquery": { "_cache": "false","query": {"query_string": {"query": qpri} }}}, {"exists": {"field": @sg_extract}},{"exists": {"field": @spri_extract}}]
                            aggr = {}
                            reqfield.each do |relm|
                              fname = "FIELD_"+relm
                              tname = relm+".raw"
                              qname = relm+":(\""+ event[relm] +"\")"
                              filter1 = {"fquery": {"_cache": "false","query": {"query_string": {"query": qname}}}}
                              filter2 = {"exists": {"field": tname}}
                              filter << filter1
                              filter << filter2
                              aggr[fname] = { "terms": { "field": tname, "size": 0, "order": {"_count": "desc"} }}
                            end
                            body = {"query": { "filtered": { "filter": { "bool": { "must": filter } } } }, "aggregations": aggr}
                            result = @client.search index: '_all', type: 'syslog', size: 0, timeout: 60, search_type: 'count', query_cache: 'false', body: body
                            reqfield.each do |fieldelm|
                              fname = "FIELD_"+fieldelm
                              cnt_relation=0
                              result['aggregations'][fname]['buckets'].each do |raggr|
                                cnt_relation=cnt_relation+raggr['doc_count'].to_i
                              end
                              if cnt_relation == 0
                                #relation no exist
                                rnote=rnote+4
                                rdesc << "Value of field:"+name+ " relation with another fields not existe..."
                              elsif not cnt_relation > comprelation
                                rnote=rnote+2
                                rdesc << "Value of field:"+name+ " relation with another fields is low."
                              end
                            end
                          end
                          #divise note par name.size
                          event["risk_note"]=rnote/name.size
                          event["risk_desc"]=rdesc
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
    filter_matched(event)
  end
end



