rule Trojan_Win64_CbatStrike_A_2147754337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CbatStrike.A!MTB"
        threat_id = "2147754337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CbatStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 54 24 24 41 0f b6 cc 44 0a e6 f6 d1 40 0f b6 c6 48 83 c5 01 f6 d0 be 04 00 00 00 0a c8 41 22 cc 49 83 ed 01 88 4d ff 8b 4c 24 20 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 28 00 00 00 00 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 44 8b c5 33 d2 41 ff d4 48 8b f8 44 8b cd 4c 8b c0 48 8b d6 48 8b 0d ?? ?? ?? ?? 41 ff d5 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

