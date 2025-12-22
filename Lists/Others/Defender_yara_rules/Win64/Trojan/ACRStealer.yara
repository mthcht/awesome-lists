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

