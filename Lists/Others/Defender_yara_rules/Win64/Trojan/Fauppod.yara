rule Trojan_Win64_Fauppod_ML_2147888888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fauppod.ML!MTB"
        threat_id = "2147888888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b d0 48 2b d8 44 8b cf 0f 1f 00 41 0f b6 c8 32 0c 13 88 0a 41 80 c0 05 48 8d 52 01 49 83 e9 01 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fauppod_MN_2147892929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fauppod.MN!MTB"
        threat_id = "2147892929"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 48 89 e5 48 83 ec 20 48 8b 05 86 8d 00 00 ff d0 48 8b 05 9d 8d 00 00 ff d0 ba 00 00 00 00 48 89 c1 48 8b 05 4c 8e 00 00 ff d0 48 8d 05 23 2c 00 00 48 89 c1 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

