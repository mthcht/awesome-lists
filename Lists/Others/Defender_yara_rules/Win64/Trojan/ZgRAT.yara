rule Trojan_Win64_ZgRAT_A_2147899811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZgRAT.A!MTB"
        threat_id = "2147899811"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 00 83 f8 ff 74 ?? a8 10 75 ?? 48 8d 0d ?? ?? ?? 00 ff 15 ?? ?? 02 00 83 f8 ff 74 ?? a8 10 75 ?? 48 8d 0d ?? ?? ?? 00 ff 15 ?? ?? 02 00 83 f8 ff 0f 84 ?? ?? 00 00 a8 10 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZgRAT_AZ_2147900858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZgRAT.AZ!MTB"
        threat_id = "2147900858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ba 65 38 32 38 63 35 61 33 48 89 54 24 1c 48 ba 38 35 37 37 65 34 64 31 48 89 54 24 24 48 ba 63 30 62 37 64 33 34 39 48 89 54 24 2c 48 ba 33 63 36 36 37 31 35 35 48 89 54 24 34 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

