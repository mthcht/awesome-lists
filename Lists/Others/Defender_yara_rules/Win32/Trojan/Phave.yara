rule Trojan_Win32_Phave_KK_2147946086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phave.KK!MTB"
        threat_id = "2147946086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 40 00 c7 45 ?? 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 8d 45 ?? 89 44 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 45 ?? 89 04 24 8b 45 dc}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 45 f4 3b 45 0c 73 33 8b 55 08 8b 45 f4 8d 0c 02 8b 55 08 8b 45 f4 01 d0 0f b6 00 89 c3 8b 45 f4 ba 00 00 00 00 f7 75 f0 8b 45 10 01 d0 0f b6 00 31 d8 88 01 83 45 f4 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

