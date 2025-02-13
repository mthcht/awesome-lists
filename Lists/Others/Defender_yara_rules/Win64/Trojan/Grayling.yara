rule Trojan_Win64_Grayling_LKA_2147895765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Grayling.LKA!MTB"
        threat_id = "2147895765"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Grayling"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e8 08 88 84 24 e1 01 00 00 8b c1 c1 e8 10 45 8d 41 06 88 84 24 e2 01 00 00 0f b6 44 24 22 88 84 24 e4 01 00 00 0f b7 44 24 22 c1 e9 18 66 c1 e8 08 88 8c 24 e3 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

