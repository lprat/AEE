<head>
<title>ELASTICSEARCH ANOMALIE GESTION -- lionel.prat9@gmail.com</title>
</head>
<body>
<center><h1>MANAGE ANOMALIE DATABASE - POC (experimental and no secure code)</h1></center><hr>
<h3>FORMULAIRE MODIFICATION ANOMALIE DATABASE</h3>
<script>var cnt=0;</script>
<form method="POST" action="<?php echo $_SERVER[PHP_SELF];?>">
 <label style="display:block;fload:left;width: 150px">Id number :</label><input type="text" name="idnumber"><br>
 <label style="display:block;fload:left;width: 150px">Key name :</label><input type="text" name="keyname"><br>
 <div id="testx"><label style="display:block;fload:left;width: 150px">Key value :</label><input type="text" name="keyvalue"><br></div>
 <a href="#" onclick='javascript:if(cnt==0){document.getElementById("testx").innerHTML = "<label style=\"display:block;fload:left;width: 150px\">Key value[0] :</label><input type=\"tex
t\" name=\"keyvalue[0]\"><br>";cnt++;}else{document.getElementById("testx").innerHTML = document.getElementById("testx").innerHTML+"<label style=\"display:block;fload:left;width: 150px
\">Key value["+cnt+"] :</label><input type=\"text\" name=\"keyvalue["+cnt+"]\"><br>";cnt++;}'>ADD ARRAY</a><br>
 <input type="submit" name="submit" value="Submit Form"><br>
</form>
<hr>
<?php
function findkeys($array,$mykey){
  if(array_key_exists($mykey,$array)) return $array[$mykey];
  foreach($array as $key => $value){
   if(is_array($value)) return findkeys($value,$mykey);
  }
 return false;
}
function test($e){
 return "$e";
}
require 'vendor/autoload.php';
$params = array();
$params['hosts'] = array('http://localhost:3306');
$client = new Elasticsearch\Client($params);
//UPDATE
if(isset($_POST['idnumber'])){
  if(isset($_POST['keyname'])){
    if(isset($_POST['keyvalue'])){
      $key = $_POST['keyname'];
      $val = $_POST['keyvalue'];
      $idn = $_POST['idnumber'];
      // get mapping pour voir si array/string/interger/hash...
      $parmx = array();
      $parmx['index'] = 'anomalie';
      $parmx['field'] = $key;
      $ret = $client->indices()->getFieldMapping($parmx);  
      $type=findkeys($ret,'type');
      if($type == 'long'){
        $val=intval($val);
      }
      //if(!is_array($_GET['keyvalue'])){ 
        //print("Modification:<br> $key => $val <br> type: $type");
      //} else {
        print("Modification:<br> $key => ");
        print_r($val);
        print(" <br> type: $type<br>");
      //}
      $parmx = array();
$parmx['body'] = <<<'EOT'
{ "update": { "_id": $idn, "_type"; "sig", "_index": "anomalie" } }
{ "doc": {$key: $val} }

EOT;
      //$ret = $client->bulk($parmx);   
      print("Veuillez patienter...<br>");
      sleep(15);
      print("Mise a jour => OK<br><hr>");
    }
  }
}

$sp = array();
$sp['index'] = 'anomalie';
$sp['size'] = 1000;
$sp['timeout'] = 60;
$json = '{ "query": { "match_all": {}}}';
$sp['body'] = $json;
$result = $client->search($sp);
$baseanook = array();
//print_r($result);
if(!empty($result['hits']['hits'])){
  foreach($result['hits']['hits'] as $elemx) {
    $basesig = array();
    $infocomp = array();
    $basepri = array();
    foreach($elemx['_source'] as $nkey => $nval) {
      if (($nkey != 'SG') and ($nkey != 'PRI') and ($nkey != 'SIGF') and ($nkey != 'SIG-TERMS')) {
        $infocomp[$nkey] = $nval;
      }
      $infocomp['_id'] = $elemx['_id'];
      $infocomp['_index'] = $elemx['_index'];
      $infocomp['_type'] = $elemx['_type'];
      ksort($infocomp);
      $basesig[$elemx['_source']['SIGF']] = $infocomp;
      $basepri[$elemx['_source']['PRI']] = $basesig;
      if(!array_key_exists($elemx['_source']['SG'],$baseanook)){
        $baseanook[$elemx['_source']['SG']] = $basepri;
      }else{
        if(!array_key_exists($elemx['_source']['PRI'],$baseanook[$elemx['_source']['SG']])){
          $baseanook[$elemx['_source']['SG']][$elemx['_source']['PRI']] = $basesig;
        }else{
          $baseanook[$elemx['_source']['SG']][$elemx['_source']['PRI']][$elemx['_source']['SIGF']] = $infocomp;
        }
      }
    }
  }
}
$cnt=0;
foreach($baseanook as $nkey => $nval){
  print("<a href=\"#\" onclick='javascript:if(document.getElementById(\"id_div_".$cnt."\").style.display == \"block\"){document.getElementById(\"id_div_".$cnt."\").style.display=\"none
\"}else{document.getElementById(\"id_div_".$cnt."\").style.display=\"block\"}'>SG: $nkey</a><br>\n");
  print("<div id=\"id_div_".$cnt."\" style=\"display:none;margin-left:20px;width=100px;background:red\">\n");
  $cntp=0;
  foreach ($nval as $n2key => $n2val){
    print("<a href=\"#\" onclick='javascript:if(document.getElementById(\"id_div2_".$cntp."_".$cnt."\").style.display == \"block\"){document.getElementById(\"id_div2_".$cntp."_".$cnt."
\").style.display=\"none\"}else{document.getElementById(\"id_div2_".$cntp."_".$cnt."\").style.display=\"block\"}'>PRI: $n2key</a><br>\n");
    print("<div id=\"id_div2_".$cntp."_".$cnt."\" style=\"display:none;margin-left:40px;width=100px;background:green\">\n");
    $cntsig=0;
    foreach ($n2val as $n3key => $n3val){
      print("<a href=\"#\" onclick='javascript:if(document.getElementById(\"id_div3_".$cntsig."_".$cntp."_".$cnt."\").style.display == \"block\"){document.getElementById(\"id_div3_".$c
ntsig."_".$cntp."_".$cnt."\").style.display=\"none\"}else{document.getElementById(\"id_div3_".$cntsig."_".$cntp."_".$cnt."\").style.display=\"block\"}'>SIG: $n3key</a><br>\n");
      print("<div id=\"id_div3_".$cntsig."_".$cntp."_".$cnt."\" style=\"display:none;margin-left:60px;width=100px;background:white\">\n");
      foreach ($n3val as $n4key => $n4val){
        if(is_array($n4val)){
         print("<span style=\"color:red;text-decoration:underline;\">$n4key:</span> <span>");
         print_r($n4val);
         print("</span><br>\n");
        } else {
         print("<span style=\"color:red;text-decoration:underline;\">$n4key:</span> <span>$n4val</span><br>\n");
        }
      }
      print("</div><br>\n");
      $cntsig++;
    }
    print("</div><br>\n");
    $cntp++;
  }
  print("</div><br><hr>\n");
  $cnt++;
}
?>
</body>
</html>

