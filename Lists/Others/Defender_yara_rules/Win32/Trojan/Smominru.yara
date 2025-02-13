rule Trojan_Win32_Smominru_A_2147724993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smominru.A"
        threat_id = "2147724993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smominru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "64.myxmr.pw:8888/64.rar" ascii //weight: 1
        $x_1_2 = "64.myxmr.pw:8888/cc.rar" ascii //weight: 1
        $x_1_3 = "xmr.5b6b7b.ru:8888/xmrok.txt" ascii //weight: 1
        $x_1_4 = "c:\\windows\\debug\\lsmose.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

