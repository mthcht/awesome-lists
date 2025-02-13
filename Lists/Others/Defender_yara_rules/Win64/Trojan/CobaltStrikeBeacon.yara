rule Trojan_Win64_CobaltStrikeBeacon_LKA_2147888518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeBeacon.LKA!MTB"
        threat_id = "2147888518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 01 0f b7 04 24 66 ff c8 66 89 04 24 48 8b 44 24 ?? 48 83 c0 04 48 89 44 24 38 48 8b 44 24 ?? 48 83 c0 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeBeacon_LKB_2147888519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeBeacon.LKB!MTB"
        threat_id = "2147888519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 28 39 04 24 73 ?? 8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeBeacon_YY_2147897118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeBeacon.YY!MTB"
        threat_id = "2147897118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 ca 8a 8c 0d ?? ?? ?? ?? 30 0e 46 4f fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? 88 94 05 ?? ?? ?? ?? 02 ca 8a 8c 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikeBeacon_EM_2147898410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeBeacon.EM!MTB"
        threat_id = "2147898410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {33 c9 4d 8d 40 01 48 83 fa 15 48 0f 45 ca 41 ff c1 42 0f b6 04 11 48 8d 51 01 41 30 40 ff 41 81 f9 cc 01 00 00 72 d9}  //weight: 4, accuracy: High
        $x_1_2 = "mysuperdupersecretkey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

