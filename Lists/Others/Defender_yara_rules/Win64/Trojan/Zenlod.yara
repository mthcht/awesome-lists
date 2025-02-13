rule Trojan_Win64_Zenlod_RPX_2147849057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenlod.RPX!MTB"
        threat_id = "2147849057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenlod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba c0 0b 00 00 31 c9 41 b8 00 30 00 00 41 b9 40 00 00 00 e8 ?? ?? ?? ?? 48 89 c6 48 85 c0 0f 84 88 11 00 00 0f 28 05 87 88 1e 00 0f 11 06 0f 28 05 8d 88 1e 00 0f 11 46 10 0f 28 05 92 88 1e 00 0f 11 46 20 0f 28 05 97 88 1e 00 0f 11 46 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zenlod_NZ_2147899320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenlod.NZ!MTB"
        threat_id = "2147899320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenlod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 c1 e2 20 48 0b d0 48 89 55 ?? 48 8b 45 10 24 ?? 3c 06 75 32 8b 05 49 78 01 00 83 c8 08}  //weight: 5, accuracy: Low
        $x_5_2 = {eb 14 e8 78 4f 00 00 84 c0 75 09 33 c9 e8 95 24 00 00 eb ea 8a c3 48 83 c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

