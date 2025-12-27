rule Trojan_Win64_Ghanarava_GVA_2147948845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ghanarava.GVA!MTB"
        threat_id = "2147948845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ghanarava"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f3 0f 7e 04 11 66 0f ef c9 4c 8d 04 53 89 c2 83 e2 f8 66 0f 64 c8 66 0f 6f d0 01 d6 66 0f 60 c1 66 0f 60 d1 66 0f 70 c0 4e 66 41 0f d6 10 66 41 0f d6 40 08 a8 07 0f 84 8a 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 63 d2 66 0f be 14 11 66 89 54 03 06 8d 56 04 39 d7 7e 35}  //weight: 1, accuracy: High
        $x_1_3 = "/second.html" ascii //weight: 1
        $x_1_4 = "mpowershell -enc \"%hs" wide //weight: 1
        $x_1_5 = "*** stack smashing detected ***: terminated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

