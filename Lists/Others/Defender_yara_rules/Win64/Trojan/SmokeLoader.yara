rule Trojan_Win64_SmokeLoader_RPQ_2147846187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SmokeLoader.RPQ!MTB"
        threat_id = "2147846187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d0 48 89 c1 48 89 4c 24 50 48 8d 54 24 60 4d 33 c0 4d 33 c9 c7 44 24 20 02 00 00 80 48 c7 44 24 28 00 00 00 00 ff d6 48 89 44 24 48 48 33 c9 c7 c2 80 84 1e 00 41 c7 c0 00 10 00 00 41 c7 c1 04 00 00 00 ff d3 48 89 44 24 58 48 8b 4c 24 48 48 8b 54 24 58 41 c7 c0 80 84 1e 00 4c 8d 8c 24 0c 01 00 00 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SmokeLoader_LR_2147980988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SmokeLoader.LR!MTB"
        threat_id = "2147980988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {83 e2 07 8d 3c 02 8b 45 fc 8b d3 c1 ff 03 8b 5d f4 0f af f9 8b 4d 08 0f af d6 8a 04 08 0f b6 c9 03 d7 03 da 0f af df 2b 5d f8 2b de 32 c3 85 f6 8b 75 08 0f b6 c0 0f 45 c8 8b 45 fc 88 0c 30 8b 75 10 8b 45 10 03 f7}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

