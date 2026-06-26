rule Trojan_Win32_KongTuke_PAA_2147972439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KongTuke.PAA!MTB"
        threat_id = "2147972439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KongTuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 4d d8 c1 c1 0c 03 d1 33 f2 89 55 cc 8b 55 ec c1 c6 08 03 d6 89 75 dc 8b 75 e4 03 75 d4 33 fe 89 55 ec 33 d1 c1 c7 10}  //weight: 3, accuracy: High
        $x_2_2 = {8b 4b 0c 31 48 fc 8b 4b 10 31 08 8b 4b 14 31 48 04 8b 4b 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

