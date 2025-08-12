rule Trojan_Win64_OyesterLoader_OSH_2147922580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.OSH!MTB"
        threat_id = "2147922580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 59 10 48 8b d3 48 8b 4a 60 45 8b ce 48 8b c1 66 44 39 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OyesterLoader_C_2147949039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.C!MTB"
        threat_id = "2147949039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 48 83 ec 20 48 8b 35 ?? ?? ?? ?? 48 8b 0e 48 8d ?? ?? ?? ?? 00 ba 01 00 00 00 45 31 c0 ff d0 b8 ?? ?? ?? ?? 48 03 06 48 83 c4 20 5e 48 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

