rule Trojan_Win32_Rimecud_A_2147632583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rimecud.gen!A"
        threat_id = "2147632583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d2 45 ff 8a 4d 10 2a cb 32 4d ff fe c3 88 0e 3a d8 75 02 32 db fe c2}  //weight: 1, accuracy: High
        $x_1_2 = {eb 0b 68 c8 00 00 00 ff 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? ff d3 85 c0 74 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rimecud_A_2147632584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rimecud.A"
        threat_id = "2147632584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 14 b8 04 00 00 00 f7 e1 83 c0 14 03 c5 ff 30 83 e8 04 e2 f9 ff 55 f8}  //weight: 1, accuracy: High
        $x_1_2 = {ff 50 08 68 a4 38 00 00 8b 45 08 ff b0 ?? ?? ?? ?? 6a 02 68 ?? ?? ?? ?? 8b 45 08 ff b0 ?? ?? ?? ?? ff 75 08 e8 ?? ?? ?? ?? 83 c4 18 3d 02 01 00 00 75 04 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 08 8b 40 06 3b 81 ?? ?? ?? ?? 74 05 e9 ?? ?? ?? ?? 8b 45 08 8b 80 ?? ?? ?? ?? 8b 40 04 35}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 00 4d 8b 45 fc c6 40 01 3a 8b 45 fc c6 40 02 20 8b 45 fc 83 c0 03 89 45 fc 8b 45 f4 83 c0 03}  //weight: 1, accuracy: High
        $x_1_5 = {ff 50 4f 8b 4d 08 89 41 05 8b 45 08 83 78 05 ff 75 04 33 c0 eb 2d 8d 45 fc 50 68 7e 66 04 80}  //weight: 1, accuracy: High
        $x_1_6 = {33 c1 8b 4d 08 03 4d f8 88 01 8b 55 08 03 55 f8 0f b6 02 8b 4d f8 83 e1 03 0f b6 c9 d3 e0 88 45 ff eb bf}  //weight: 1, accuracy: High
        $x_1_7 = {75 49 83 7d f0 00 76 43 8b 45 fc ff 70 04 8d 85 ?? ?? ?? ?? 50 8b 45 08 ff 50 ?? 85 c0 75 25 ff 75 f4 6a 01}  //weight: 1, accuracy: Low
        $x_1_8 = {0f b6 45 10 83 e0 02 74 10 c7 45 f8 02 00 00 00 c7 45 f0 11 00 00 00 eb 0e c7 45 f8 01 00 00 00 c7 45 f0 06 00 00 00 ff 75 f0 ff 75 f8 6a 02 6a 03}  //weight: 1, accuracy: High
        $x_1_9 = {81 78 04 19 02 00 00 0f 85 ?? ?? ?? ?? 8b 45 10 81 78 08 00 80 00 00 0f 85 ?? ?? ?? ?? 8b 85 78 ff ff ff 83 78 04 02 0f 85 ?? ?? ?? ?? 8b 45 10 8b 40 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Rimecud_ARMI_2147929807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rimecud.ARMI!MTB"
        threat_id = "2147929807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 55 68 d7 4a 4a 00 64 ff 30 64 89 20 8b c3 8b 10 ff 52 ?? ba f0 4a 4a 00 8b c3 8b 08 ff 51 ?? 8d 45 f8 8b 4d fc ba 10 4b 4a 00 e8 ?? ?? ?? ?? 8b 55 f8 8b c3 8b 08 ff 51 ?? ba 28 4b 4a 00 8b c3 8b 08 ff 51 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

