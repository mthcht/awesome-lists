rule Trojan_Win64_Phonzy_AHB_2147947502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phonzy.AHB!MTB"
        threat_id = "2147947502"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phonzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {81 f1 20 83 b8 ed f6 c2 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 20 83 b8 ed f6 c1 01 0f 44 d0 8b ca d1 e9 8b c1 35 20 83 b8 ed f6 c2 01 0f 44 c1 41 0f b7 08 66 85 c9 0f}  //weight: 3, accuracy: High
        $x_2_2 = {c7 44 24 50 0c 00 00 00 66 48 0f 7e c8 48 c1 e8 20 89 44 24 54 66 0f 6f c1 66 0f 73 d8 08 66 0f 7e 44 24 58 66 0f 73 d9 08 66 48 0f 7e c8 48 c1 e8 20 89 44 24 5c 89 4c 24 60 48 8d 4c 24 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

