rule Trojan_Win64_BigpipeLoader_RPY_2147835185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BigpipeLoader.RPY!MTB"
        threat_id = "2147835185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BigpipeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 29 45 fc 48 8b 45 10 48 8b 00 8b 55 ec 89 d2 48 01 c2 48 8b 45 10 48 89 10 48 8b 45 18 8b 10 8b 45 ec 01 c2 48 8b 45 18 89 10 83 7d fc 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BigpipeLoader_RPZ_2147835186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BigpipeLoader.RPZ!MTB"
        threat_id = "2147835186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BigpipeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 13 4c 8d 4c 24 40 48 83 64 24 20 00 44 8b c7 48 8b cd ff 15 ?? ?? ?? ?? 85 c0 74 0d 8b 4c 24 40 48 01 0b 01 0e 2b f9 75 d5}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8d 4d ef 4c 89 6c 24 20 44 8b c7 48 8b d3 49 8b ce ff 15 ?? ?? ?? ?? 85 c0 74 0c 8b 4d ef 48 03 d9 03 f1 2b f9 75 d8}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8d 4d ef 4c 89 6c 24 20 44 8b c3 49 8b d7 48 8b ce ff 15 ?? ?? ?? ?? 85 c0 74 0c 8b 4d ef 4c 03 f9 03 f9 2b d9 75 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

