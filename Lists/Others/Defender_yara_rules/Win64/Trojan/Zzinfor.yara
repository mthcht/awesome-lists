rule Trojan_Win64_Zzinfor_LK_2147845627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zzinfor.LK!MTB"
        threat_id = "2147845627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zzinfor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 b9 04 00 00 00 41 b8 00 10 00 00 8b d0 33 c9 ff}  //weight: 2, accuracy: High
        $x_1_2 = {8a 06 48 83 c6 01 88 07 48 83 c7 01 49 c7 c1 02 00 00 00 02 d2 75 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zzinfor_EC_2147850523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zzinfor.EC!MTB"
        threat_id = "2147850523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zzinfor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 e2 7f 03 c2 83 e0 7f 2b c2 8b d0 48 63 4c 24 78 48 8b 44 24 70 88 14 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

