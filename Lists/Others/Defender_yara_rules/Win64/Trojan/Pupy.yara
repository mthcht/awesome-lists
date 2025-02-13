rule Trojan_Win64_Pupy_MA_2147838365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pupy.MA!MTB"
        threat_id = "2147838365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pupy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {57 ba 58 3f 15 5a b9 75 ee 40 70 56 53 48 83 ec 30 48 c7 44 24 24 48 b8 00 00 c7 44 24 2c 00 00 ff e0 e8 ?? ?? ?? ?? ba 8d f1 4f 84 b9 75 ee 40 70 48 89 c3 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {c6 44 24 3f 00 48 8d 54 24 32 45 31 c9 48 b9 66 69 6c 65 2e 78 6c 73 48 89 4c 24 37 4c 8d 44 24 37 31 c9 c7 44 24 32 6f 70 65 6e c6 44 24 36 00 c7 44 24 28 01 00 00 00 48 c7 44 24 20 00 00 00 00 ff d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

