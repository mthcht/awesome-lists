rule Trojan_Win64_Dapato_NA_2147950686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.NA!MTB"
        threat_id = "2147950686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4c 63 25 8f cd 0f 00 41 8d 4c 24 01 48 63 c9 48 c1 e1 03 e8 56 93 01 00 49 89 c5 48 85 c0 74 57}  //weight: 2, accuracy: High
        $x_1_2 = {e8 73 92 01 00 4c 8b 05 5c cf 0f 00 8b 0d 66 cf 0f 00 4c 89 00 48 8b 15 54 cf 0f 00 e8 f7 ba 0c 00 8b 0d 39 cf 0f 00 85 c9 0f 84 fb 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dapato_SX_2147964062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.SX!MTB"
        threat_id = "2147964062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 45 03 c5 4d 03 cd 41 83 f8}  //weight: 10, accuracy: Low
        $x_10_2 = {41 f7 e0 c1 ea ?? 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 45 03 c4 4d 03 cc 41 83 f8}  //weight: 10, accuracy: Low
        $x_50_3 = {48 33 d8 48 89 5d ?? 48 c7 01 00 00 00 00 33 c9 48 8d 15 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 2e}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Dapato_ARR_2147970348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.ARR!MTB"
        threat_id = "2147970348"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 0f b7 c3 41 2a c9 c0 e1 ?? 66 41 d3 e8 41 80 e0 0f 41 80 f8 0a 1a c0 41 ff c1 24 ?? 04 ?? 41 02 c0 41 88 02 49 ff c2}  //weight: 10, accuracy: Low
        $x_5_2 = "sr_deploy.log" ascii //weight: 5
        $x_3_3 = "XOR done, MZ=%c%c size=%u" ascii //weight: 3
        $x_2_4 = "Run() isMemory=%d ip=%s port=%d startup=%d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dapato_AHA_2147971243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.AHA!MTB"
        threat_id = "2147971243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {2e 0f 1f 84 00 00 00 00 00 83 f0 ?? 48 83 c2 01 48 83 c1 01 88 41 ff 41 0f b6 04 10 84 c0 75}  //weight: 30, accuracy: Low
        $x_20_2 = {88 84 24 83 00 00 00 0f b6 42 05 88 44 24 60 8b 42 18 89 84 24}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dapato_LR_2147972302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.LR!MTB"
        threat_id = "2147972302"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8b 44 24 40 8b 00 39 44 24 30 0f ?? ?? ?? ?? 00 8b 44 24 30 48 6b c0 0c 48 8b 4c 24 40 8b 54 24 58 39 54 01 04 0f ?? ?? ?? ?? 00 8b 44 24 30 48 6b c0 0c 48 8b 4c 24 40 8b 54 24 5c 39 54 01 08}  //weight: 20, accuracy: Low
        $x_10_2 = {48 89 4c 24 08 57 48 8b 44 24 10 48 8d ?? ?? ?? ?? ?? 48 89 08 48 8b 44 24 10 48 83 c0 08 48 8b f8 33 c0 b9 10 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

