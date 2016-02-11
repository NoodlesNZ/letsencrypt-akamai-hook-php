#!/usr/bin/env php
<?php
require __DIR__ . '/vendor/autoload.php';

$result = LayerShifter\TLDExtract\Extract::get($argv[2]);

if (empty($result)) {
  die("Can't find zone");
}

$zone = $result->domain . '.' . $result->tld;

$action = $argv[1];

switch ($action) {
  case 'deploy_challenge':
    deploy_challenge();
    break;
  case 'clean_challenge':
    clean_challenge();
    break;
}

function deploy_challenge()
{
  global $argv, $zone;
  
  $client = \Akamai\Open\EdgeGrid\Client::createFromEdgeRcFile();
  
  $response = $client->get("/config-dns/v1/zones/$zone");
  
  $domain = str_replace(".{$zone}", '', $argv[2]);
  
  $dns = json_decode($response->getBody());
  
  $dns->zone->soa->serial++;
  
  $dns->zone->txt[] = array('target' => $argv[4], 'active' => true, 'name' => "_acme-challenge.{$domain}", 'ttl' => 1);
  
  $json = json_encode($dns);
  
  try {
    $client->post("/config-dns/v1/zones/$zone", [
        'body' => $json,
        'headers' => ['Content-Type' => 'application/json']
    ]);
  } catch (GuzzleHttp\Exception\ServerException $e) {
    echo "An error occurred: " .$e->getMessage(). "\n";
  }
  
  $count = 0;
  
  while (has_dns_propagated("_acme-challenge.{$domain}.{$zone}", $argv[4]) === false) {
    echo " + DNS not propagated, waiting 30s...\n";
    sleep(30);
  }
}

function clean_challenge()
{
  global $argv, $zone;
  
  $client = \Akamai\Open\EdgeGrid\Client::createFromEdgeRcFile();
  
  $response = $client->get("/config-dns/v1/zones/$zone");
  
  $dns = json_decode($response->getBody());
  
  $dns->zone->soa->serial++;
  
  $domain = str_replace(".{$zone}", '', $argv[2]);
  
  foreach ($dns->zone->txt as $k => $txt) {
    if ($txt->name == "_acme-challenge.{$domain}") {
      array_splice($dns->zone->txt, $k, 1);
      break;
    }
  }
  
  $json = json_encode($dns);
  
  try {
    $client->post("/config-dns/v1/zones/$zone", [
        'body' => $json,
        'headers' => ['Content-Type' => 'application/json']
    ]);
  } catch (GuzzleHttp\Exception\ServerException $e) {
    echo "An error occurred: " .$e->getMessage(). "\n";
  }
}

function has_dns_propagated($domain, $token)
{
  //use a public DNS server as that's what Let's Encrypt will use
  $ns = array('8.8.8.8', '8.8.4.4');
  
  try {
    $r = new Net_DNS2_Resolver(array('nameservers' => $ns));
    $result = $r->query($domain, 'TXT');
  } catch (Net_DNS2_Exception $e) {
    return false;
  }
  
  if ($result->answer[0]->text[0] == $token) {
    return true;
  }
  else {
    return false;
  }
}


