rule TrojanProxy_Win32_Dittacka_A_2147727866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dittacka.A"
        threat_id = "2147727866"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dittacka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "socks\\SocksMgr.cpp" ascii //weight: 1
        $x_1_2 = "socks\\SocksParser.cpp" ascii //weight: 1
        $x_1_3 = "Proxy Error!" ascii //weight: 1
        $x_1_4 = "QUERY DNS Error" ascii //weight: 1
        $x_2_5 = "Tunnel thread finish!" ascii //weight: 2
        $x_2_6 = "Accept faild!" ascii //weight: 2
        $x_2_7 = "Bind %d faild!" ascii //weight: 2
        $x_2_8 = "disire DomainName : %s" ascii //weight: 2
        $x_2_9 = "destination port : %d" ascii //weight: 2
        $x_3_10 = {73 79 73 74 65 6d 00 00 5b 00 44 00 5d 00 00 00 5b 00 2b 00 5d 00 00 00 5b 00 2d 00 5d 00 00 00 5b 00 3f 00 5d 00 00 00 25 00 73 00 20 00 00 00}  //weight: 3, accuracy: High
        $x_2_11 = {66 0f d6 45 ?? 66 0f d6 45 ?? ff 15 ?? ?? ?? ?? 66 89 45 ?? b8 02 00 00 00 6a 00 66 89 45 ?? ff 15 ?? ?? ?? ?? 6a 04 89 45 ?? 8d 45 ?? 50 6a 04 68 ff ff 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

