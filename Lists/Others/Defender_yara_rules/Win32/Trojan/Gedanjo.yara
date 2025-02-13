rule Trojan_Win32_Gedanjo_A_2147627635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gedanjo.A"
        threat_id = "2147627635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gedanjo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Start.htm?AreaID=" ascii //weight: 1
        $x_1_2 = "8800.org" ascii //weight: 1
        $x_1_3 = "LastStartTime_%d" ascii //weight: 1
        $x_1_4 = ".cn/ExeIni14/Messenger.txt" ascii //weight: 1
        $x_1_5 = "facepizza.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

