rule TrojanProxy_Win32_Bobax_A_2147583847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bobax.A"
        threat_id = "2147583847"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "service pack 2" ascii //weight: 10
        $x_10_2 = "\\drivers\\tcpip.sys" ascii //weight: 10
        $x_10_3 = {4e 54 34 00 2e 4e 45 54 00 00 00 00 20 44 61 74 61 43 65 6e 74 65 72 53 72 76 00 00 20 41 64 76 53 72 76 00 20 45 6e 74 53 72 76 00 20 57 65 62 53 72 76}  //weight: 10, accuracy: High
        $x_1_4 = "http://www.ip2location.biz/" ascii //weight: 1
        $x_1_5 = "http://www.grokster.com/" ascii //weight: 1
        $x_1_6 = "http://www.edpsciences.org/htbin/ipaddress" ascii //weight: 1
        $x_1_7 = "http://www.myipaddress.com/" ascii //weight: 1
        $x_1_8 = "http://www.whatismyip.com/" ascii //weight: 1
        $x_1_9 = "http://www.ipchicken.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

