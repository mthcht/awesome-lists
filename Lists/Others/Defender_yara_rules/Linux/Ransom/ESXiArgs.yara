rule Ransom_Linux_ESXiArgs_B_2147841400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ESXiArgs.B!MTB"
        threat_id = "2147841400"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ESXiArgs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 7d e8 e8 [0-6] 48 83 7d d0 4f 76 ?? 48 8b 7d e8 48 83 c7 30 48 8b 55 d8 48 8b 75 e0 b9 50 00 00 00 e8 [0-6] 48 83 45 e0 50 48 83 45 d8 50 48 83 6d d0 50 eb ?? 48 8b 7d e8 48 83 c7 30 48 8b 4d d0 48 8b 55 d8 48 8b 75 e0 e8 [0-6] 48 8b 45 d0 89 c2 48 8b 45 e8 89 90 80 00 00 00 48 c7 45 d0 00 00 00 00 48 83 7d d0 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_ESXiArgs_C_2147904637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ESXiArgs.C!MTB"
        threat_id = "2147904637"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ESXiArgs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 89 45 d0 8b 45 fc 89 45 b8 8b 45 fc 89 c2 c1 e2 08 8b 45 fc c1 e8 18 89 c0 8b 04 85 e0 92 60 00 89 d1 31 c1 8b 45 f0 89 c2 c1 ea 08 0f b6 45 f0 89 c0 8b 04 85 e0 96 60 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

