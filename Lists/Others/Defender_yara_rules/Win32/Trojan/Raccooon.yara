rule Trojan_Win32_Raccooon_RI_2147829840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccooon.RI!MTB"
        threat_id = "2147829840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccooon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 89 54 24 08 89 0c 24 c7 44 24 04 00 00 00 00 8b 44 24 08 01 44 24 04 8b 44 24 04 31 04 24 8b 04 24 83 c4 0c c3 [0-16] 81 01 e1 34 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

