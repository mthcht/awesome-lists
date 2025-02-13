rule Trojan_Win32_Rlsloup_A_2147616744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rlsloup.gen!A"
        threat_id = "2147616744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rlsloup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 22 81 bd ?? ?? ff ff 5c 3f 3f 5c 8d 85 ?? ?? ff ff 74 06 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {74 22 be 0e 00 00 c0 56 68 ?? ?? ?? ?? e8 ?? ?? ff ff 59 59 57 6a 12}  //weight: 1, accuracy: Low
        $x_1_3 = {46 83 f8 74 59 75 55 0f be 06 50 e8 ?? ?? 00 00 46 83 f8 70 59 75 45 8a 06 46 3c 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 8f 37 01 00 00 03 c7 89 45 e8 33 c0 83 c1 f0 74 2c ba}  //weight: 1, accuracy: High
        $x_1_5 = {30 14 0e 40 25 ff 00 00 00 46 3b 75 e4 72 ea 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Rlsloup_B_2147620740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rlsloup.B"
        threat_id = "2147620740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rlsloup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 75 70 6c 6f 61 64 73 2f 64 64 75 6d 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 55 54 00 5c 4d 69 6e 69 64 75 6d 70 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff d5 85 c0 0f 84 ?? 00 00 00 8b 4c 24 20 8d 51 02 b8 ab aa aa aa f7 e2 8b f2 d1 ee 03 f6 03 f6 51 8b c6 e8 ?? ?? ff ff 83 c4 04 8d 44 24 24 50 56 68 ?? ?? ?? ?? 57 ff d3}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 38 28 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 83 c2 02 b8 ab aa aa aa f7 e2 53 6a 08 d1 ea 53 8d 44 24 3c 03 d2 50 03 d2 57 89 54 24 60 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Rlsloup_B_2147623146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rlsloup.gen!B"
        threat_id = "2147623146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rlsloup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 26 68 0e 00 00 c0 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 08 53 6a 12}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 25 3d 5c 3f 3f 5c 75 0f 8d 84 24 ?? ?? 00 00 50 8d 4c 24 ?? 51 eb 0d 8d 94 24 ?? ?? 00 00 52 8d 44 24 ?? 50 ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 7a 3c 03 fa c7 47 58 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

