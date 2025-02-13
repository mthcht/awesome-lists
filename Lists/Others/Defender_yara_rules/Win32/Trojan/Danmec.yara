rule Trojan_Win32_Danmec_A_2147601621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.gen!A"
        threat_id = "2147601621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 0d 74 2d 33 c9 c7 45 fc 09 00 00 00 8a 54 0d f8 49 3a 54 0d ed 75 04 88 54 0d e5 ff 4d fc 75 ec 3c 0a 75 06 c6 04 3e 00 eb 05 34 1b 88 04 3e 46 43 3b 5d 0c 72 c3}  //weight: 1, accuracy: High
        $x_1_2 = {76 20 8a 0c 1f 84 c9 74 09 80 f1 1b 88 0c 02 42 eb 0b c6 04 02 0d c6 44 02 01 0a 42 42 47 3b fe 72 e0 c6 04 02 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 0d 74 10 3c 0a 75 06 c6 04 3e 00 eb 05 34 1b 88 04 3e 46 ?? 3b [0-3] 72}  //weight: 1, accuracy: Low
        $x_1_4 = {49 3a 54 0d ?? 75 04 88 54 0d ?? ?? 75 ee 3c 0a 75 09 8b 45 ?? c6 04 06 00 eb 08 8b 4d ?? 34 1b 88 04 0e 46 ?? 3b ?? 0c 72}  //weight: 1, accuracy: Low
        $x_1_5 = {68 24 30 40 00 ?? ff 15 3c 20 40 00 83 c4 08 85 c0 75 22 8b 94 24 0c 01 00 00 68 d0 07 00 00 ?? 56 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {74 1d 0f b6 ?? ?? 0f b6 ?? ?? 33 ?? 8b ?? f8 03 ?? ?? 88 ?? 8b ?? ?? 83 ?? 01 89 ?? ?? eb 1c 8b ?? f8 03 ?? ?? c6 ?? 0d 8b ?? f8 03 ?? ?? c6 ?? 01 0a}  //weight: 1, accuracy: Low
        $x_1_7 = {84 d2 74 09 80 f2 1b 88 14 01 41 eb 0c c6 04 01 0d c6 44 01 01 0a 83 c1 02 46 3b f7 72 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Danmec_B_2147603686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.gen!B"
        threat_id = "2147603686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 0d 74 1f 6a 02 59 49 8a d9 d0 e3 85 c9 88 5c 0d fc 75 f3 3c 0a 75 05 88 0c 3e eb 05 34 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danmec_C_2147608996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.gen!C"
        threat_id = "2147608996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 0d 74 10 3c 0a 75 06 c6 04 1e 00 eb 05 34 1b 88 04 1e 46 ?? 3b [0-3] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 0d 74 27 6a 09 33 c9 5b 8a 54 0d f4 49 3a 54 0d e9 75 04 88 54 0d e1 4b 75 ee 3c 0a 75 06 c6 04 3e 00 eb 05 34 1b 88 04 3e 46 8b 4d f8 41 3b 4d 0c 89 4d f8 72 b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Danmec_D_2147619589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.gen!D"
        threat_id = "2147619589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 73 33 38 36 2e 69 6e 69 00}  //weight: 2, accuracy: High
        $x_1_2 = {61 73 70 69 6d 67 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 69 63 72 6f 73 6f 66 74 5c 53 66 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 62 33 32 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {6c 67 33 32 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 4d 44 52 45 50 4f 52 54 2e 42 49 4e 00}  //weight: 1, accuracy: High
        $x_4_7 = {34 1b 88 04 1f 43 46 8a 06 84 c0 74 ?? 0f be c0 40 85 c0 74 07 46 48 80 3e 00 75 f5}  //weight: 4, accuracy: Low
        $x_4_8 = {3c 0d 74 0f 3c 0a 75 05 88 0c 1e eb 05 34 1b 88 04 1e 46 ?? 3b [0-3] 72}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Danmec_F_2147628624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.gen!F"
        threat_id = "2147628624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 1e 34 1f 88 04 1f 43 46 8a 06 84 c0 74 15 0f be c0 40 85 c0 74 07 46 48 80 3e 00 75 f5 8a 06 84 c0 75 de 57 51 c6 04 1f 00}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Sft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danmec_J_2147628720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.J"
        threat_id = "2147628720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 6d 73 77 69 6e 33 32 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 73 74 5f 78 33 32 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 73 62 63 74 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {3c 73 69 64 3e 25 73 3c 2f 73 69 64 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danmec_L_2147649964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.L"
        threat_id = "2147649964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 01 8b 85 ?? ?? ff ff 88 94 05 ?? ?? ff ff e9 ?? ?? ff ff 14 00 8b 8d ?? ?? ff ff 0f be 94 0d ?? ?? ff ff 2b 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 fc 0f 00 45 fc 33 c9 39 45 fc 0f 95 c1 8b c1 8b e5 5d c3 [0-7] 8b 08 8b 11 81 c2 00 00 00 40 56 89 15 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Danmec_M_2147649968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.M"
        threat_id = "2147649968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "401"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {33 c9 85 c0 7e 09 80 34 31 1b 41 3b c8 7c f7 [0-9] c3 e9}  //weight: 100, accuracy: Low
        $x_100_2 = {33 c9 85 ff 7e 19 6a 02 5a 4a 8a c2 d0 e0 85 d2 88 44 15 fc 75 f3 80 34 31 1b 41 3b cf 7c e7 5f 5e c9 c3 e9}  //weight: 100, accuracy: High
        $x_100_3 = "GET %s%s HTTP/1.1" ascii //weight: 100
        $x_100_4 = "Microsoft ASPI Manager" ascii //weight: 100
        $x_100_5 = "Software\\Microsoft\\Sft" ascii //weight: 100
        $x_1_6 = "216.40.204.106:80" ascii //weight: 1
        $x_1_7 = "216.69.164.173:80" ascii //weight: 1
        $x_1_8 = "208.109.25.64:80" ascii //weight: 1
        $x_1_9 = "208.109.50.117:80" ascii //weight: 1
        $x_1_10 = "208.109.51.140:80" ascii //weight: 1
        $x_1_11 = "208.109.124.137:80" ascii //weight: 1
        $x_1_12 = "208.109.198.121:80" ascii //weight: 1
        $x_1_13 = "74.52.72.58:80" ascii //weight: 1
        $x_1_14 = "67.18.156.178:80" ascii //weight: 1
        $x_1_15 = "67.19.9.186:80" ascii //weight: 1
        $x_1_16 = "67.18.151.202:80" ascii //weight: 1
        $x_1_17 = "win.ini" ascii //weight: 1
        $x_1_18 = "phishing" ascii //weight: 1
        $x_1_19 = "SMTPServer" ascii //weight: 1
        $x_1_20 = "SMTPAUTH" ascii //weight: 1
        $x_1_21 = "MAIL FROM:" ascii //weight: 1
        $x_1_22 = "RCPT TO:" ascii //weight: 1
        $x_1_23 = "MS IE FTP Passwords" ascii //weight: 1
        $x_1_24 = "INETCOMM Server Passwords" ascii //weight: 1
        $x_1_25 = "Outlook Account Manager Passwords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_1_*))) or
            ((5 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Danmec_N_2147650917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Danmec.N"
        threat_id = "2147650917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6d 61 69 6c 71 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 46 06 ff 45 fc 83 45 f8 28 39 45 fc 7c ?? 8b 46 28 03 45 08 89 85 ?? ?? ff ff 8d 85 ?? ?? ff ff 50 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

