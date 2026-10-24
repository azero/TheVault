<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$dir=getenv('CLOSEDDOOR_DIR'); require $dir.'/src/bootstrap.php'; closeddoor_load_config();
use ClosedDoor\Repo\{Access,Clients,Users};
$url=rtrim($argv[1],'/');$run=bin2hex(random_bytes(4));$secret=Clients::newSecret();$id='app_'.bin2hex(random_bytes(12));
$pk=ClosedDoor\Db::insert('INSERT INTO clients (client_id,name,secret_hash,redirect_uris,post_logout_uris,launch_url,active,created_at) VALUES (?,?,?,?,?,?,1,?)',[$id,'TheVault test '.$run,Clients::hashSecret($secret),json_encode([$url.'/auth/callback']),json_encode([$url.'/login']),$url.'/',db_time()]);
$notes=ClosedDoor\Db::insert('INSERT INTO clients (client_id,name,secret_hash,redirect_uris,post_logout_uris,launch_url,active,created_at) VALUES (?,?,?,?,?,?,1,?)',['app_'.bin2hex(random_bytes(12)),'Notes test '.$run,Clients::hashSecret(Clients::newSecret()),json_encode(['https://notes.example/callback']),json_encode([]),'https://notes.example/',db_time()]);
$email='rail'.$run.'@example.com';$pass='disposable long test passphrase';$uid=Users::create($email,'Rail Test',$pass,false);Access::replaceForUser($uid,[$pk=>'admin',$notes=>'']);
echo json_encode(['client_id'=>$id,'client_secret'=>$secret,'email'=>$email,'password'=>$pass,'uid'=>$uid,'notes_pk'=>$notes]);
