<?php
class Crypto
{

	public function encode($str){
		if($str == null || $str == ''){
			return $str;
		}
		return base64_encode($str);
	}

	public function decode($str){
		if($str == null || $str == ''){
			return $str;
		}
		return base64_decode($str);
	}
}
?>