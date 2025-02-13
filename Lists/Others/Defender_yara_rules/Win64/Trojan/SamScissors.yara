rule Trojan_Win64_SamScissors_EM_2147844198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SamScissors.EM!MTB"
        threat_id = "2147844198"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SamScissors"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 03 d6 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 0f 44 2b f1 41 ff c6 44 89 6c 24 30 4c 89 6c 24 38}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SamScissors_EM_2147844198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SamScissors.EM!MTB"
        threat_id = "2147844198"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SamScissors"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 89 c1 49 c1 e9 3f 49 c1 e8 21 45 01 c8 41 c1 e0 02 47 8d 04 40 44 29 c2 8a 14 0a 88 94 04 50 04 00 00}  //weight: 2, accuracy: High
        $x_3_2 = {8a 94 04 50 03 00 00 00 d1 02 8c 04 50 04 00 00 44 0f b6 c1 46 8a 8c 04 50 03 00 00 42 88 94 04 50 03}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

