rule Trojan_Win32_NetWalker_AMTB_2147963479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWalker!AMTB"
        threat_id = "2147963479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 34 95 04 dc 44 00 8b d7 c1 ea 0a 83 e2 3f 83 e3 3f c1 ef 10 33 34 95 04 de 44 00 33 d2 8a d5 33 34 9d 04 dd 44 00}  //weight: 5, accuracy: High
        $x_1_2 = "netwalker" ascii //weight: 1
        $x_1_3 = "rdpcIip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

