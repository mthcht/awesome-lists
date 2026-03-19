rule Trojan_Win64_ACRStealer_ETL_2147944753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.ETL!MTB"
        threat_id = "2147944753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 44 24 20 48 c7 40 10 12 00 00 00 48 8d 0d f8 a0 01 00 48 89 48 08 48 8b 4c 24 38 48 89 4c 24 30 48 8d 05 40 8d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_GVA_2147959906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.GVA!MTB"
        threat_id = "2147959906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 15 e0 ac 81 00 48 8b 45 f8 48 01 d0 44 0f b6 00 b9 76 00 00 00 48 8b 45 f8 ba 00 00 00 00 48 f7 f1 48 8d 05 3d b1 81 00 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 8d 3f 4d 87 d2 48 83 45 f8 01 b8 16 00 00 00 48 39 45 f8 72 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_NUA_2147965160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.NUA!MTB"
        threat_id = "2147965160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 48 0f 2a c0 0f 28 c8 f3 0f 59 4b 1c 0f 2f ca 72 0c f3 0f 5c ca 0f 2f ca}  //weight: 1, accuracy: High
        $x_2_2 = {f6 44 01 03 0f 74 0b 0f b6 44 01 03 83 e0 f0 4c 03 c8 4c 33 ca 49 8b c9 5b e9 f1 3a ff ff cc}  //weight: 2, accuracy: High
        $x_2_3 = {48 89 9c 24 b0 40 00 00 48 89 ac 24 b8 40 00 00 48 8b 05 0a 06 05 00 48 33 c4 48 89 84 24 60 40 00 00 4c 8b f2 48 8b d9 48 85 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

