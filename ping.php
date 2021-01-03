<?php
/*
* ICMP_PING
* 通过设置ICMP报文和首部中的TTL字段来实现
* 本地记录数据包的往返时间
*/
define('MICROSECOND', 1000000); // 1秒 = 1000000 微秒
define('SOL_IP', 0); // 这两项要用常量
define('IP_TTL', 2);

if(!isset($argv[1])){
	die('
	用法: php ping.php [-i ttl] [-c count] [-w timeout]
	选项:
		-c  num     设置Ping指定主机的次数
                -i  num     设置最大的TTL，默认为255
                -w  num     设置等待回复的超时时间
                -f  file    设置从文件中读取IP地址或者域名
                
');
}
if (!in_array('-f', $argv)) {
    $host = end($argv); // 主机地址永远取最后一个值
    $ip = host2ip($host);
} else {
    $ip = 0;
}
$id  = rand(0, 0xFFFF);
$seq = 1;//初始seq的值
$ttl = 255; // 缺省ttl设置为255
$MaxHops = 255;
$send_count = 0; // 发送包数量
$recv_count = 0; // 接收包的数量
$WaitTime = 1; // 默认等待时间
if(in_array('-c',$argv)){
	$arr = array_keys($argv,"-c");
	$index = $arr[0]+1;
	if($argv[$index]<=0|$argv[$index]>255){
		die('输入值(-c)无效\n');
	}
	else{
		$MaxHops = $argv[$index];
	}
}

if(in_array('-i',$argv)){
	$arr = array_keys($argv,"-i");
	$index = $arr[0]+1;
	if($argv[$index]<=0|$argv[$index]>255){
		die('输入值(-i)无效\n');
	}
	else{
		$ttl = $argv[$index];
	}
}

if(in_array('-w',$argv)){
	$arr = array_keys($argv,"-w");
	$index = $arr[0]+1;
	if($argv[$index]<=0|$argv[$index]>255){
		die('输入值(-w)无效\n');
	}
	else{
		$WaitTime = $argv[$index];
	}
}
if (in_array('-f', $argv)) {
    $arr = array_keys($argv, '-f');
    $index = $arr[0] + 1;
    $filename = $argv[$index];
    @$myfile = fopen($filename, 'r') or die('文件打开失败');
    $ip = host2ip(fgets($myfile)); // 调用函数，校验IP地址或域名转换IP
        echo "这是$ip";
    fclose($myfile);
}

$sock = @socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp')) or die ('创建套接字错误');

echo "正在Ping $host ($ip)\n";

while(true) {
	
	//最外层循环，负责ICMP报文的构造和发送
	socket_set_option($sock, SOL_IP, IP_TTL, $ttl);
	
	//构造8字节的ICMP头部分
	$packet = '';
	$packet .= chr(8); // 类型
	$packet .= chr(0); // 代码
	$packet .= chr(0); // 校验和
	$packet .= chr(0); // 校验和
	$packet .= chr($id & 0xFF); // 标识符
	$packet .= chr($id >> 8  ); // 标识符
	$packet .= chr($seq & 0xFF); // 序号
	$packet .= chr($seq >> 8  ); // 序号

	//构造56字节的ICMP数据部分(空白填充)
	for ($i = 0; $i < 56; ++$i) { 
		$packet .= chr(0);
	}

	$CheckSum = CheckSum($packet); //设置校验和

	$packet[2] = $CheckSum[0];
	$packet[3] = $CheckSum[1];

	$start   = microtime(true) * MICROSECOND;
	$timeout = $start + MICROSECOND*$WaitTime;

//        for($i=0;$i<3;$i++){
            socket_sendto($sock, $packet, strlen($packet), 0, $ip, 0) or die ('发送数据报错误'); // ICMP 没有端口号的概念，所以用0
//        }

	for (;;) {
		
		$now = microtime(true) * MICROSECOND;
		
		if ($now >= $timeout) {
			
			echo "*\n";
			break; // 如果发送IP数据报发送超时，跳出循环，直接进行下一次发送操作
		}
		
		$read  = array($sock);
		$write = $other = array();

		$selected = socket_select($read, $write, $other, 0, $timeout - $now); // 使用非阻塞方式监控变化

		if ($selected === 0) {
			
			echo "*\n";
			break; // 超出了规定的时间，跳出循环，直接进行下一次发包操作
		}
		else {
			
			socket_recvfrom($sock, $data, 65535, 0, $return_ip, $rport);

			$data = unpack('C*', $data);//解包

			//判断是否为我们需要的ICMP数据包
			if (
				($data[10] == 1) && // 如果IP数据报头的第十个八位字段值为1，代表此包为ICMP包
				($data[21] == 0)&&//如果为0代表为回送应答
				($data[25] == ($id & 0xFF))&& // 标识符
				($data[26] == ($id >> 8))&& // 标识符
				($data[27] == ($seq & 0xFF))&& // 序号
				($data[28] == ($seq >> 8)) //序号
			) {
				$now  = microtime(true) * MICROSECOND;
				$time = round(($now - $start) / 1000, 1);
				echo "来自 " . $return_ip . " 的回复：字节= ".(count($data)-20)." 时间= ".$time." ms seq= ".$seq."\n";
				break;
			}
		}
	}
	sleep(1);
	++$seq;
	if($seq>$MaxHops){
		break;
	}
}

//计算校验和
function CheckSum($data) {
	$bit = unpack('n*', $data);
	$sum = array_sum($bit);

	if (strlen($data) % 2) {
		$temp = unpack('C*', $data[strlen($data) - 1]);
		$sum += $temp[1];
	}

	$sum  = ($sum >> 16) + ($sum & 0xffff);
	$sum += ($sum >> 16);

	return pack('n*', ~$sum);
}
// 传入IP或域名，返回IP
function host2ip($host) {
    $host = trim($host); // 移除无关格式
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $host;
    } else {
        $ip = gethostbyname($host);
        if ($ip === $host) {
            die("无效的主机名称:$host\n");
        }
        return $ip;
    }
}
?>