rule Trojan_Win32_Ghostrat_RPW_2147838257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostrat.RPW!MTB"
        threat_id = "2147838257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 c6 45 ec 41 c6 45 ed 44 c6 45 ee 56 c6 45 ef 41 c6 45 f0 50 c6 45 f1 49 c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c 88 5d f8 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ghostrat_RPZ_2147846275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostrat.RPZ!MTB"
        threat_id = "2147846275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 83 c6 04 83 c3 02 3b 7d f4 72 b8 eb 1d 0f b7 0b 3b 4d f0 77 15 8b 45 ec 8b 40 1c 8d 04 88 8b 4d fc 8b 04 08 03 c1 74 02 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ghostrat_RPY_2147848820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostrat.RPY!MTB"
        threat_id = "2147848820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 85 f8 fe ff ff eb 03 8d 49 00 8a 10 3a 11 75 1a 84 d2 74 12 8a 50 01 3a 51 01 75 0e 83 c0 02 83 c1 02 84 d2 75 e4 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 13 8d 95 d4 fe ff ff 52 56 e8}  //weight: 1, accuracy: High
        $x_1_2 = "explorer.exe" ascii //weight: 1
        $x_1_3 = "CheckServer\\Tcs.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ghostrat_RPX_2147851473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostrat.RPX!MTB"
        threat_id = "2147851473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f2 ff d0 99 b9 0a 00 00 00 f7 f9 42 83 ee 00 74 13 83 ee 01 74 0a 83 ee 01 75 0b 0f af fa eb 06 2b fa eb 02 03 fa 83 ad a8 f5 ff ff 01 8b 35}  //weight: 1, accuracy: High
        $x_1_2 = "ShellcodeBase64Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

