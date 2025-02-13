rule Backdoor_Win32_Fakeqipserv_2147616611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fakeqipserv"
        threat_id = "2147616611"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeqipserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://marketingg.jino-net.ru/proxy/gate.php" ascii //weight: 1
        $x_1_2 = "HTTPProxyServer1" ascii //weight: 1
        $x_1_3 = {57 69 6e 64 6f 77 73 5f 56 69 64 65 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = "ServiceTableEntryArray" ascii //weight: 1
        $x_1_5 = "ProxyPassword<" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

