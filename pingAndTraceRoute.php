<?php
/*
 * ping and traceroute
 * 支持icmp,udp,tcp三种实现方式
 */
define('MICROSECOND', 1000000); // 1秒 = 1000000 微秒
define('SOL_IP', 0); // 这两项要用常量
define('IP_TTL', 2);

if (!isset($argv[1])) {
    die('
	用法: php ICMP_TraceRoute.php	[-h maximum_hops] [-w timeout] [-g]
	     [-u] [-tcp] [-i] traget_name
	选项: 
                -c          num     设置每秒发送包的数量，默认为十个                
		-max_ttl    num     设置探测的最大跳数
                -first_ttl  num     设置首个发送包中的TTL值
                -interval   num     设置ICMP请求间隔,默认为0
                -port       num     设置TCP、UDP模式下的目标端口号
                -localport  num     设置TCP、UDP模式下的源端口
		-w          num     设置等待回复的超时时间
                -psize      num     设置ping数据包的大小
                -f          file    从文件中读取IP地址或域名
		-g                  显示路由节点的地理位置
		-u                  使用udp方式
		-tcp                使用tcp方式
		-i                  使用icmp方式，默认为该方式
');
}

if (!in_array('-f', $argv)) {
    $host = end($argv); // 主机地址永远取最后一个值
    $ip = host2ip($host);
} else {
    $ip = 0;
}
select();

// 初始的选择
function select() {
    global $argv;
    global $ip;
    if (in_array('-u', $argv)) {
        udp($ip);
    } else if (in_array('-i', $argv)) {
        icmp($ip);
    } else if (in_array('-tcp', $argv)) {
        tcp($ip);
    } else {
        icmp($ip);
    }
}

// 传入IP地址，开始ping
function ping($arr) {
    global $argv;
    echo "正在测试各节点连通性\n";
    $id = rand(0, 0xFFFF);
    $seq = 1; //初始seq的值
    $temp = 1;
    $ttl = 255; // 缺省ttl设置为255
    $send_count = 0; // 发送包数量
    $recv_count = 0; // 接收包的数量
    $MaxHops = 1;

    $sock = socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp')) or die('创建套接字错误');

    foreach ($arr as $value) {
        if ($value != '*') {
            while (true) {
                echo "$temp\t";
                //构造8字节的ICMP头部分
                $packet = '';
                $packet .= chr(8); // 类型
                $packet .= chr(0); // 代码
                $packet .= chr(0); // 校验和
                $packet .= chr(0); // 校验和
                $packet .= chr($id & 0xFF); // 标识符
                $packet .= chr($id >> 8)
                ; // 标识符
                $packet .= chr($seq & 0xFF); // 序号
                $packet .= chr($seq >> 8); // 序号
                //构造56字节的ICMP数据部分(空白填充)
                for ($i = 0; $i < 56; ++$i) {
                    $packet .= chr(0);
                }
                $CheckSum = CheckSum($packet); //设置校验和

                $packet[2] = $CheckSum[0];
                $packet[3] = $CheckSum[1];

                $start = microtime(true) * MICROSECOND;
                $timeout = $start + MICROSECOND * 2;

                //只需要自己构建ICMP数据报，IP头在发送数据之前会自动填充
                for ($i = 0; $i < 10; $i++) {
                    // 发送三次数据进行探测，提高结果的精确度
                    socket_sendto($sock, $packet, strlen($packet), 0, $value, 0) or die('发送数据报错误'); // ICMP 没有端口号的概念，所以用0
                }
                for (;;) {
                    $now = microtime(true) * MICROSECOND;
                    if ($now >= $timeout) {
                        echo "*\n";
                        break; // 如果发送IP数据报发送超时，跳出循环，直接进行下一次发送操作
                    }

                    $read = array($sock);
                    $write = $other = array();

                    $selected = socket_select($read, $write, $other, 0, $timeout - $now); // 使用非阻塞方式监控变化

                    if ($selected === 0) {
                        echo "*\n";
                        break; // 超出了规定的时间，跳出循环，直接进行下一次发包操作
                    } else {
                        socket_recvfrom($sock, $data, 65535, 0, $return_ip, $rport);
                        $data = unpack('C*', $data); //解包
                        //判断是否为我们需要的ICMP数据包
                        if (
                                ($data[10] == 1) && // 如果IP数据报头的第十个八位字段值为1，代表此包为ICMP包
                                ($data[21] == 0) && //如果为0代表为回送应答
                                ($data[25] == ($id & 0xFF)) && // 标识符
                                ($data[26] == ($id >> 8)) && // 标识符
                                ($data[27] == ($seq & 0xFF)) && // 序号
                                ($data[28] == ($seq >> 8)) //序号
                        ) {
                            $now = microtime(true) * MICROSECOND;
                            $time = round(($now - $start) / 1000, 1);
                            echo "$return_ip\t$time ms\n";
                            break;
                        }
                    }
                }
                ++$seq;
                if ($seq > $MaxHops) {
                    break;
                }
            }
        } else {
            echo "$temp\t*\n";
        }
        $temp++;
    }
    socket_close($sock);
}

// 匹配IP地址
function matchIp($unknown) {
    $pat = "/^(((1?\d{1,2})|(2[0-4]\d)|(25[0-5]))\.){3}((1?\d{1,2})|(2[0-4]\d)|(25[0-5]))$/";
    if (preg_match($pat, $unknown)) {
        return $unknown;
    } else {
        return '404';
    }
}

// 计算校验和
function CheckSum($data) {
    $bit = unpack('n*', $data);
    $sum = array_sum($bit);

    if (strlen($data) % 2) {
        $temp = unpack('C*', $data[strlen($data) - 1]);
        $sum += $temp[1];
    }

    $sum = ($sum >> 16) + ($sum & 0xffff);
    $sum += ($sum >> 16);

    return pack('n*', ~$sum);
}

// 构造ICMP报文，传入id和seq，返回icmp数据包
function structIcmp($id, $seq) {

    //构造8字节的ICMP头部分
    $packet = '';
    $packet .= chr(8); // 类型
    $packet .= chr(0); // 代码
    $packet .= chr(0); // 校验和
    $packet .= chr(0); // 校验和
    $packet .= chr($id & 0xFF); // 标识符 & 0xFF保留低八位
    $packet .= chr($id >> 8); // 标识符
    $packet .= chr($seq & 0xFF); // 序号
    $packet .= chr($seq >> 8); // 序号
    //构造56字节的ICMP数据部分(空白填充)
    for ($i = 0; $i < 56; ++$i) {
        $packet .= chr(0);
    }

    $CheckSum = checksum($packet); //设置校验和

    $packet[2] = $CheckSum[0];
    $packet[3] = $CheckSum[1];

    return $packet;
}

// 传入IP，以icmp方式进行
function icmp($ip) {
    global $argv;
    $geograph = 0;
    $seq = 1; // 初始ttl的值
    $MaxHops = 30; // 初始的最大ttl值
    $WaitTime = 1; // 1ms
    $id = rand(0, 0xFFFF);
    $success = 1;
    $packcount = 10;
    $sleeptime = 0;
    if (in_array('-max_ttl', $argv)) {
        $arr = array_keys($argv, '-max_ttl');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-max_ttl)无效');
        } else {
            $MaxHops = $argv[$index];
        }
    }
    if (in_array('-first_ttl', $argv)) {
        $arr = array_keys($argv, '-first_ttl');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-first_ttl)无效');
        } else {
            $seq = $argv[$index];
        }
    }
    if (in_array('-interval', $argv)) {
        $arr = array_keys($argv, '-interval');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-interval)无效');
        } else {
            $sleeptime = $argv[$index];
        }
    }
    if (in_array('-w', $argv)) {
        $arr = array_keys($argv, '-w');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-w)无效');
        } else {
            $WaitTime = $argv[$index];
        }
    }
    if (in_array('-c', $argv)) {
        $arr = array_keys($argv, '-c');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-c)无效');
        } else {
            $packcount = $argv[$index];
        }
    }
    if (in_array('-f', $argv)) {
        $arr = array_keys($argv, '-f');
        $index = $arr[0] + 1;
        $filename = $argv[$index];
        @$myfile = fopen($filename, 'r') or die('文件打开失败');
        $ip = host2ip(fgets($myfile)); // 调用函数，校验IP地址或域名转换IP
        fclose($myfile);
    }
    if (in_array('-g', $argv)) {
        $geograph = 1; // 解析节点的地理位置
    }

    $sock = @socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp')) or die('创建套接字错误');
    
    echo "正在跟踪到 $ip 的路由(ICMP)\n";
    
    while ($success == 1) {
        //最外层循环，负责ICMP报文的构造和发送

        socket_set_option($sock, SOL_IP, IP_TTL, $seq);

        echo "$seq\t";

        $packet = structIcmp($id, $seq);

        $start = microtime(true) * MICROSECOND; //设置开始时间

        $timeout = $start + MICROSECOND; //设置发送超时时间为1ms
        //只需要自己构建ICMP数据报，IP头在发送数据之前会自动填充
        for ($i = 0; $i < $packcount; $i++) {
            // 发送十次数据进行探测，提高结果的精确度
            socket_sendto($sock, $packet, strlen($packet), 0, $ip, 0) or die('发送数据报错误'); // ICMP 没有端口号的概念，所以用0
        }

        for (;;) {
            //内层循环，负责数据报的超时判断、接收、类型判断、对应返回包判断、解包、读取
            $now = microtime(true) * MICROSECOND;
            if ($now >= $timeout) {
                echo "*\n"; //发送超时
                $saveIp[$seq] = '*'; // 记录IP地址
                break; // 如果发送IP数据报发送超时，跳出循环，直接进行下一次发送操作
            }

            $read = array($sock);
            $other = array();
            $selected = socket_select($read, $other, $other, 0, $WaitTime * 1000000); // 使用非阻塞方式监控变化

            if ($selected === 0) {
                echo "*\n";
                $saveIp[$seq] = '*'; // 记录IP地址
                break; // 超出了规定的时间，跳出循环，直接进行下一次发包操作
            } else {
                socket_recvfrom($sock, $data, 65535, 0, $return_ip, $return_port);

                $data = unpack('C*', $data); //解包
                //判断是否为ICMP数据包
                if ($data[10] != 1) { // 如果IP数据报头的第十个八位字段值为1，代表此包为ICMP包
                    continue; //如果不是ICMP数据包，中止本次循环，继续下次循环，接收下一个包进行判断
                }

                $found = 0;

                //判断是否为我们需要的ICMP数据包
                if (
                        ($data[21] == 0) && //如果为0代表为回送应答
                        ($data[25] == ($id & 0xFF)) && // 标识符
                        ($data[26] == ($id >> 8)) && // 标识符
                        ($data[27] == ($seq & 0xFF)) && // 序号
                        ($data[28] == ($seq >> 8)) //序号
                ) {
                    $found = 1;
                } else if (
                        ($data[21] == 11) && // 如果为11代表超时
                        //				(count($data) >= 56) &&
                        ($data[53] == ($id & 0xFF)) && // 标识符
                        ($data[54] == ($id >> 8)) && // 标识符
                        ($data[55] == ($seq & 0xFF)) && // 序号
                        ($data[56] == ($seq >> 8)) //序号
                ) {
                    $found = 2;
                }
                //如果有数据包为ICMP数据包，但是不是自己要的ICMP数据包，则继续循环，进行接收，直到数据包符合要求跳出循环，进行下次发包
                //符合我们要求
                if ($found) {
                    $result = "$return_ip"; // 输出结果
                    $saveIp[$seq] = $return_ip; // 记录IP地址
                    if ($geograph)
                        $result .= ' '.getlocation($return_ip);
                    echo "$result\n";
                    if ($found == 1) { // 到达目标
                        echo "已达到目标地址\n";
                        $success = 0;
                        break;
                    }
                    break;
                }
            }
        }
        ++$seq;
        if ($seq > $MaxHops) {
            break;
        }
            sleep($sleeptime);
    }
   
    socket_close($sock);
    
    for($i=0;$i<3;$i++){
        ping($saveIp); // 对得到的IP地址进行ping
    }
}

// 传入IP，以udp方式进行
function udp($ip) {
    $geograph = 0;
    global $argv;
    $WaitTime = 1; // 1ms
    $ttl = 1; // 初始的ttl值
    $MaxHops = 30;
    $success = 1;
    $packcount = 10;
    $sleeptime = 0; // 发送数据包的时间间隔
    $islocalport = false;
    if (in_array('-max_ttl', $argv)) {
        $arr = array_keys($argv, '-max_ttl');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-max_ttl)无效');
        } else {
            $MaxHops = $argv[$index];
        }
    }
    if (in_array('-first_ttl', $argv)) {
        $arr = array_keys($argv, '-first_ttl');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-first_ttl)无效');
        } else {
            $ttl = $argv[$index];
        }
    }
    if (in_array('-port', $argv)) {
        $arr = array_keys($argv, '-port');
        $index = $arr[0] + 1;
        if ($argv[$index] < 0) {
            die('输入值(-port)无效');
        } else {
            $port = $argv[$index];
            $isport = true;
        }
    }
    if (in_array('-localport', $argv)) {
        $arr = array_keys($argv, '-localport');
        $index = $arr[0] + 1;
        if ($argv[$index] < 0) {
            die('输入值(-localport)无效');
        } else {
            // 未完成
        }
    }
    if (in_array('-w', $argv)) {
        $arr = array_keys($argv, '-w');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-w)无效');
        } else {
            $WaitTime = $argv[$index];
        }
    }
    if (in_array('-c', $argv)) {
        $arr = array_keys($argv, '-c');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-c)无效');
        } else {
            $packcount = $argv[$index];
        }
    }
    if (in_array('-interval', $argv)) {
        $arr = array_keys($argv, '-interval');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-interval)无效');
        } else {
            $sleeptime = $argv[$index];
        }
    }
    if (in_array('-f', $argv)) {
        $arr = array_keys($argv, '-f');
        $index = $arr[0] + 1;
        $filename = $argv[$index];
        @$myfile = fopen($filename, 'r') or die('文件打开失败');
        $ip = host2ip(fgets($myfile)); // 调用函数，校验IP地址或域名转换IP
        fclose($myfile);
    }
    if (in_array('-g', $argv)) {
        $geograph = 1; // 解析节点的地理位置
    }
    echo "正在跟踪到 $ip 的路由(UDP)\n";
    while ($success) {

        echo "$ttl\t";
        $dst_port = rand(33434, 65535); // 随机端口号，作为标识
        $data_3 = "";
        $icmp_socket = socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp')) or die('创建icmp socket 错误'); // 接收ICMP差错报文
        $udp_socket = socket_create(AF_INET, SOCK_DGRAM, getprotobyname('udp')) or die('创建udp socket 错误'); // 发送UDP
        socket_set_option($udp_socket, SOL_IP, IP_TTL, $ttl) or die('设置套接字选项错误');
        $start = microtime(true) * MICROSECOND; //设置开始时间
        $timeout = $start + MICROSECOND; //设置发送超时时间为1ms
        for($i=0;$i<$packcount;$i++){
            if(!$isport){
                socket_sendto($udp_socket, "", 0, 0, $ip, $dst_port);
            }else{
                socket_sendto($udp_socket, "", 0, 0, $ip, $port);
            }
            
        }

        for (;;) {
            $now = microtime(true) * MICROSECOND;
            
            if ($now >= $timeout) {
                echo "*\n";
                $saveIp[$ttl] = '*'; // 记录IP地址
                break; // 如果发送IP数据报发送超时，跳出循环，直接进行下一次发送操作
            }
            
            $read = [$icmp_socket];
            $write = $other = [];
            $selected = socket_select($read, $write, $other, 0, $WaitTime * 1000000);
            
            if ($selected === 0) {
                echo "*\n";
                $saveIp[$ttl] = '*'; // 记录IP地址
                break; // 超出了规定的时间，跳出循环，直接进行下一次发包操作
            } else {
                socket_recvfrom($icmp_socket, $data, 512, 0, $return_ip, $return_port) or die('接收错误');

                $data = unpack('C*', $data); // 解包

                $data_1 = decbin($data[51]); // 把表示端口号的第一个字节的十进制形式转换为二进制

                $data_2 = decbin($data[52]); // 把表示端口号的第二个字节的十进制形式转换为二进制

                $data_3 .= $data_1 . $data_2; // 把表示端口号的完整二进制串转换为十进制

                if ((bindec($data_3) === $dst_port)||(bindec($data_3) === $port)) {
                    if ($geograph) {
                        $saveIp[$ttl] = $return_ip; // 记录IP地址
                        echo "$return_ip " . getlocation($return_ip) . "\n";
                    } else {
                        echo "$return_ip\n";
                        $saveIp[$ttl] = $return_ip; // 记录IP地址
                    }
                    if ($return_ip === $ip){
                        echo "已达到目标地址\n";
                        $success = 0;
                        break;
                    }
                    break;
                }
            }
        }

        socket_close($udp_socket);
        socket_close($icmp_socket);
        
        $ttl++;

        if ($ttl > $MaxHops) {
            break;
        }
        
        sleep($sleeptime);
    }
    ping($saveIp);
}

// 传入IP，以tcp方式进行
function tcp($ip) {
    $geograph = 0;
    global $argv;
    $MaxHops = 255;
    $sleeptime = 0; // 发送时间间隔
    $cmd = 'tcptraceroute -q 1 -n ';
//    $cmd_after = ' ';
    $port = ' ';
    if (in_array('-max_ttl', $argv)) {
        $arr = array_keys($argv, '-max_ttl');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-max_ttl)无效');
        } else {
            $MaxHops = $argv[$index];
            $cmd .= " -m $MaxHops ";
        }
    }
    if (in_array('-first_ttl', $argv)) {
        $arr = array_keys($argv, '-first_ttl');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0 | $argv[$index] > 255) {
            die('输入值(-first_ttl)无效');
        } else {
//            $MaxHops = $argv[$index];
//            $cmd .= " -m $MaxHops ";
        }
    }
    if (in_array('-interval', $argv)) {
        $arr = array_keys($argv, '-interval');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-interval)无效');
        } else {
            $sleeptime = $argv[$index];
        }
    }
    if (in_array('-localport', $argv)) {
        $arr = array_keys($argv, '-localport');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-localport)无效');
        } else {
            $localport = $argv[$index];
            $cmd .= " -p $localport ";
        }
    }
    if (in_array('-w', $argv)) {
        $arr = array_keys($argv, '-w');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-w)无效');
        } else {
            $WaitTime = $argv[$index];
            $cmd .= " -w $WaitTime ";
        }
    }
    if (in_array('-port', $argv)) {
        $arr = array_keys($argv, '-port');
        $index = $arr[0] + 1;
        if ($argv[$index] <= 0) {
            die('输入值(-port)无效');
        } else {
            $port = $argv[$index];
        }
    }
    if (in_array('-f', $argv)) {
        $arr = array_keys($argv, '-f');
        $index = $arr[0] + 1;
        $filename = $argv[$index];
        @$myfile = fopen($filename, 'r') or die('文件打开失败');
        $ip = host2ip(fgets($myfile)); // 调用函数，校验IP地址或域名转换IP
        fclose($myfile);
    }
    if (in_array('-g', $argv)) {
        $geograph = 1; // 解析节点的地理位置
    }

    $cmd .= " $ip ";
    $cmd .= $port;
    $proc = popen($cmd, 'r'); // 通过创建一个管道，产生一个子进程，执行一个shell,让我们的脚本和shell同步
    @$temp = fgets($proc); // 丢弃第一行的提示信息
    $dstip = getip($temp);
    echo "正在跟踪到 $ip 的路由(TCP)\n";
    $count = 1;
    while (!feof($proc)&&($MaxHops--)) {
        echo "$count\t";
        @$temp = trim(fgets($proc)); // 获取返回信息
        if ($geograph) {
            $temp = getip($temp);
            if($temp==='*'){
                echo "*\n";
                $saveIp[$count] = '*';
            }else{
                echo $temp.' '.getlocation($temp)."\n";
                $saveIp[$count] = $temp;
                if($dstip===$temp){
                    echo "已达到目标地址\n";
                    break;
                }
            }
        } else{
            $temp = getip($temp);
            echo "$temp\n";
            $saveIp[$count] = $temp;
            if($dstip===$temp){
                echo "已达到目标地址\n";
                break;
            }
        }
        $count++;
        sleep($sleeptime);
    }
    ping($saveIp);
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

// 传入IP，返回表示地理位置的中文字符串
function getlocation($ip) {
    //获取json文件，并提取出除了中文字符以外的其它字符
    @$location = trim(file_get_contents("http://ip.taobao.com/service/getIpInfo.php?ip=$ip"));
    $location = explode(',', $location);
    $preg = "/[\x{4e00}-\x{9fa5}]+/u";
    for ($i = 0; $i < count($location); $i++) {
        $str = $location[$i];
        if (preg_match_all($preg, $str, $matches)) {
            $result .= $matches[0][0];
        }
    }
    return $result;
}

// 传入以空格分隔的字符串，返回其中第一次出现的IP地址
function getip($str){
    $str = trim($str);
    $arr = explode(' ', $str);
    foreach($arr as $value){
        if(matchIp($value)!='404'){
            return $value;
        }
    }
    return '*';
}
?>