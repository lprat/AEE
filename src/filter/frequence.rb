# encoding: utf-8
# Filter "Frequence" analyze behavior by frequence
# POC on syslog event -- experimental version
# Contact: Lionel PRAT (lionel.prat9@gmail.com)
require "logstash/filters/base"
require "logstash/namespace"

#TODO: attribute note risk in new event special
#WARNING: the filter need more memory RAM... 

class LogStash::Filters::Frequence < LogStash::Filters::Base
  config_name "frequence"
  milestone 1

  #ES HOST
  config :hosts, :validate => :array
  # Elasticsearch index name -- BASE REF FREQ
  config :idx_name, :validate => :string, :default => "frequence"
  # Elasticsearch type name -- BASE REF FREQ
  config :type_name, :validate => :string, :default => "freq"
  #pivot 1 @source_host
  config :pivot1, :validate => :string, :default => "@source_host"
  #pivot 2 syslog_program
  config :pivot2, :validate => :string, :default => "syslog_program"
  #pivot 3 syslog_pri 
  config :pivot3, :validate => :string, :default => "syslog_pri"
  #pivot 4 status
  config :pivot4, :validate => :string, :default => "status"
  #field name: syslog_severity_code
  config :fssc, :validate => :string, :default => "syslog_severity_code"

  public
  def register
    require "elasticsearch"
    @logger.info("Frequence Base in ElasticSearch Load...", :hosts => @hosts)
    @client = Elasticsearch::Client.new hosts: @hosts
    baseano = @client.search index: idx_name, type: type_name, q: '*', size: 100000
    @baseanook = {}
    dn = Time.now()
    jn=dn.strftime("%u")
    @j_reg=jn.to_s
    cnt_sig = 0
    unless @baseano.nil?
      @logger.info(".")
      unless @baseano['hits'].nil?
        @logger.info(".")
        unless @baseano['hits']['hits'].nil?
          @logger.info("Frequence base loaded!")
          @baseano['hits']['hits'].each do |elemx|
            @baseanook = elemx['_source']
            #@logger.info("Frequence Base Loaded: ADD: #{elemx['_source']['SG']}->#{elemx['_source']['PRI']}->#{elemx['_source']['SIGF']}")
            cnt_sig=cnt_sig+1
          end
          @logger.info("Frequence Base Loaded: #{cnt_sig} sigs.")
        else
          @logger.error("Error for load frequence base...")
        end
      else
        @logger.error("Error for load frequence base...")
      end
    else
      @logger.error("Error for load frequence base...")
    end 
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    #@logger.info("ENTER FREQUENCE.")
    unless event[@pivot1].nil?
      #@logger.info("FIND SG #{event[@pivot2]}")
      unless event[@pivot2].nil?
        #@logger.info("FIND SG #{event[@pivot2]}")
        unless event[@pivot3].nil?
          #@logger.info("FIND PRI #{event[@pivot3]}")
          unless event[@pivot4].nil?
            #@logger.info("FIND STATUS #{event[@pivot4]}")
            unless @baseanook[event[@pivot1]].nil?
              #@logger.info("FIND SG REF #{@baseanook[event[@pivot2]]}")
              unless @baseanook[event[@pivot1]][event[@pivot2]].nil?
                #@logger.info("FIND SG REF #{@baseanook[event[@pivot2]]}")
                unless @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]].nil?
                  #@logger.info("FIND PRI REF #{@baseanook[event[@pivot2]][event[@pivot3]]}")
                  unless @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]].nil?
                    #check date now
                    #@logger.info("ENTER FREQUENCE. SG #{event[@pivot2]}")
                    dn = Time.now()
                    hn=dn.strftime("%k")
                    jn=dn.strftime("%u")
                    hnf=hn.to_s
                    jnf=jn.to_s
                    unless @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf].nil?
                      unless @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf].nil?
                        unless @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT'].nil?
                          if @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'].nil?
                            @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK']=0
                          end
                          @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT']=@baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT']+1
                        else
                          @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT']=1
                          @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK']=0
                        end
                      else
                        #existe mais pas de freq pour cette heure donc == 0
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]={}
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['MAX']=0
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['POURC']=100
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['REP']=0
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT']=1
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK']=0
                      end
                    else
                      #existe mais pas de freq pour ce jour donc == 0
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf]={}
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]={}
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['MAX']=0
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['POURC']=100
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['REP']=0
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT']=1
                      @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK']=0
                    end
                    #reference de freq existe
                    @logger.info("ENTER FREQUENCE. SG #{event[@pivot2]} jnf: #{jnf} hnf:#{hnf}")
                    if @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] > 0
                      #stop message to incident. - doit aller jusqu'a la boucle de mise a zero de risk et cnt
                      exit 
                    end
                    calc=0
                    rcalc=0
                    rdesc=[]
                    repa=@baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['REP']
                    cnt=@baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['CNT']
                    max=@baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['MAX']
                    #si MAX < 5 alors ne pas appliquer 20%...
                    rdesc << "Origine Max: "+max.to_s+" Origine Cnt: "+cnt.to_s
                    if max == 0
                      #deja a  + 100%
                      calc=cnt*100
                      if repa == 1
                        rcalc=cnt*100
                      end
                    else
                      if (cnt - max) < 0
                        calc=0
                      else 
                        calc=(((cnt - max).fdiv(max))*100).to_i
                      end
                      if repa == 0
                        mn=dn.strftime("%M")
                        mnf=mn.to_i
                        mnf=mnf+1
                        rmax=((max.fdiv(60))*mnf).to_i
                        if rmax == 0
                          rcalc=cnt*100
                        else
                          if (cnt - rmax) < 0
                            rcalc=0
                          else
                            rcalc=(((cnt - rmax).fdiv(rmax))*100).to_i
                          end
                        end
                      end
                      #calcule pourcentage superieur pour l'heure: ((CNT - MAX)/MAX)*100 ATTENTION SI MAX == 0, attention resultat soit negatif soit positif
                      #si superieur regarde par rapport a la journee si on a depasse jnf constant, verifie de 0 a hnf MAX & CNT
                    end
                    pourc=@baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['POURC'].to_i
                    #calcule
                    @logger.info("ENTER FREQUENCE TWO. MAX: #{max} CNT: #{cnt} rcalc: #{rcalc} comp pourc:#{pourc}") 
                    rdesc << "rcalc="+rcalc.to_s+" calc="+calc.to_s
                    if rcalc > pourc
                      risk = (((rcalc - pourc).fdiv(rcalc))*10).to_i
                      rdesc << "Risk in Hour Repartition: "+rcalc.to_s+"% reel > "+pourc.to_s+"% reg"
                      #quel est le pourcentage d'augmentation (sera le multiplicateur du risk)
                      #verification est ce qu'il y a deja eu du risque sur les heure précédentes? (si oui RISK * ??? a determiné)
                      #est qu'il s'agit de PRI ou STATUS a risque? (si oui RISK * )
                      multi=1
                      if event[@pivot4].eql?"Failure"
                        multi=multi+1
                        rdesc << "STATUS failure."
                      elsif event[@pivot4].eql?"Error"
                        multi=multi+1
                        rdesc << "STATUS error."
                      end
                      unless event[@fssc].nil?
                        if event[@fssc].to_i < 5
                          multi=multi+(5 - event[@fssc].to_i)
                          rdesc << "PRI dangerous: "+event[@fssc].to_s+"."
                        end
                      end
                      #unless event["risk_note"].nil?
                      #  rnote=event["risk_note"].to_i
                      #  if rnote > 1
                      #    multi=multi+1
                      #    rdesc << "Risk note present."
                      #  end
                      #end
                      rdesc << "Coef Risk: "+multi.to_s
                      if @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] < (risk * multi)
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] = risk * multi
                      else
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] = @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] + 1
                      end
                    elsif calc > pourc
                      #est plus grand
                      risk = (((calc - pourc).fdiv(calc))*10).to_i
                      rdesc << "Risk Globale: "+calc.to_s+"% reel > "+pourc.to_s+"% reg -- cnt:"+cnt.to_s+" max:"+max.to_s
                      #quel est le pourcentage d'augmentation (sera le multiplicateur du risk)
                      #verification est ce qu'il y a deja eu du risque sur les heure précédentes? (si oui RISK * ??? a determiné)
                      #est qu'il s'agit de PRI ou STATUS a risque? (si oui RISK * )
                      multi=1
                      if event[@pivot4].eql?"Failure"
                        multi=multi+1
                        rdesc << "STATUS failure."
                      elsif event[@pivot4].eql?"Error"
                        multi=multi+1
                        rdesc << "STATUS error."
                      end
                      unless event[@fssc].nil?
                        if event[@fssc].to_i < 5
                          multi=multi+(5 - event[@fssc].to_i)
                          rdesc << "PRI dangerous: "+event[@fssc].to_s+"."
                        end
                      end
                      #unless event["risk_note"].nil?
                      #  rnote=event["risk_note"].to_i
                      #  if rnote > 1
                      #    multi=multi+1
                      #    rdesc << "Risk note present."
                      #  end
                      #end
                      rdesc << "Coef Risk: "+multi.to_s
                      if @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] < (risk * multi)
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] = risk * multi
                      else
                        @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] = @baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK'] + 1
                      end
                    elsif calc == pourc
                      #est egale
                      #verification
                      #verification est ce qu'il y a deja eu du risque sur les heure précédentes?
                      #est qu'il s'agit de PRI ou STATUS a risque? (si oui RISK * 2)
                    else
                      #n'est pas plus grand
                      #si repa == 0 alors verifier la repartition par rapport a l'heure MAX / 60 * minute actuel = Z est ce que Z est < que COUNT ?
                      #pas de verification STOP
                    end
                    #mettre la note
                    event["risk_f_note"]=@baseanook[event[@pivot1]][event[@pivot2]][event[@pivot3]][event[@pivot4]][jnf][hnf]['RISK']
                    rdesc << "jnf: "+jnf.to_s+" hnf:"+hnf.to_s
                    event["risk_f_desc"]=rdesc
                    #remettre count et risk a zero chaque nouveau jour!
                    unless jnf.eql?@j_reg
                      @baseanook.each do |nkey,nval| 
                        nval.each do |okey,oval| 
                          oval.each do |pkey,pval| 
                            pval.each do |qkey,qval| 
                              unless qval[@j_reg].nil?
                                qval[@j_reg].each do |rkey,rval| 
                                  rval['CNT']=0
                                  rval['RISK']=0
                                end
                              end
                            end
                          end
                        end
                      end
                    end
                    @j_reg = jnf
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

