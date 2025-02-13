rule Trojan_Win32_CerenaKeeper_A_2147922668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerenaKeeper.A!MTB"
        threat_id = "2147922668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerenaKeeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1b 4c 07 24 0f 4d f2 8d 4d d0 57 e8 16 fe ff ff 80 7d d4 00 74 5a 8b 07 8b 40 04 b9 c0 01 00 00 23 4c 07 14 83 f9 40 75 0d 89 75 e0 eb 53 0f 1f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerenaKeeper_B_2147922669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerenaKeeper.B!MTB"
        threat_id = "2147922669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerenaKeeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 24 99 8b 4d f4 2b c8 8b 55 20 89 0a 8b 45 24 99 8b 4d f0 89 41 28 89 51 2c 8b 55 f0 8b 45 f4 89 42 30 8b 4d f8 89 4a 34 8b 55 f0 c6 42 6c 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 33 c9 8b 55 f4 03 42 20 13 4a 24 8b 55 f4 89 42 20 89 4a 24 8b 45 ec 03 45 f8 89 45 ec 8b 4d 0c 2b 4d f8 89 4d 0c eb 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

