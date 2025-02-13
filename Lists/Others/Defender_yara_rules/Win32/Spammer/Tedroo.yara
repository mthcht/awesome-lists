rule Spammer_Win32_Tedroo_A_2147596423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.A"
        threat_id = "2147596423"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$FAKE_NAME" ascii //weight: 1
        $x_1_2 = "%s%02d%s.%u.qmail@%s" ascii //weight: 1
        $x_1_3 = "<emails>" ascii //weight: 1
        $x_1_4 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_5 = "SPM_NET" ascii //weight: 1
        $x_1_6 = "I dont need your interest in." ascii //weight: 1
        $x_1_7 = "www.midlenet.org" ascii //weight: 1
        $x_1_8 = "s_alive.php?id=%s&tick=%u&ver=%s&smtp=%s" ascii //weight: 1
        $x_1_9 = "s_report.php?task=%u&id=%s" ascii //weight: 1
        $x_1_10 = "r00ted_" wide //weight: 1
        $x_1_11 = "(qmail %u by uid %u)" ascii //weight: 1
        $x_2_12 = {83 c0 02 83 c4 1c 3d f7 03 00 00 a3 ?? ?? ?? ?? 73 0a 81 05 ?? ?? ?? ?? f7 03 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_B_2147598016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.B"
        threat_id = "2147598016"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 68 3f 00 0f 00 30 0a 68 44 21 40 20 01 00 00 80 ff 15 0c 20 51 30 39 50 00 50 18 51 8b 14 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_C_2147598017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.C"
        threat_id = "2147598017"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 8b c1 18 cc cc cc cc cc 51 c7 70 c1 09 b8 44 23 40 00 8d 49 00 c9 0b 01 c7 0b c2 0a 22 32 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_D_2147598050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.D"
        threat_id = "2147598050"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 00 30 0a 68 ?? 21 40 20 01 00 00 80 ff 15 04 20 51 28 39 50 00 50 ?? 51 8b 14 24 50 68 72 6a 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_E_2147601773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.E"
        threat_id = "2147601773"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "285"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "http://%s/%s/s_estr.php?id=%s&str=705-%s" ascii //weight: 100
        $x_100_2 = "http://%s/%s/s_report.php?task=%u&id=%s" ascii //weight: 100
        $x_10_3 = "outpost.exe" ascii //weight: 10
        $x_10_4 = "ZAFrameWnd" ascii //weight: 10
        $x_10_5 = "MPCSVC.EXE" ascii //weight: 10
        $x_10_6 = "$FROM_EMAIL" ascii //weight: 10
        $x_10_7 = "$TO_EMAIL" ascii //weight: 10
        $x_10_8 = "InternetReadFile" ascii //weight: 10
        $x_10_9 = "WriteProcessMemory" ascii //weight: 10
        $x_10_10 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_11 = "KerioPersonalFirewallMainWindow" ascii //weight: 1
        $x_1_12 = "Norton Personal Firewall" ascii //weight: 1
        $x_1_13 = "Symantec NAMApp Class" ascii //weight: 1
        $x_1_14 = "Kaspersky Anti-Hacker" ascii //weight: 1
        $x_1_15 = "Outpost Firewall Pro" ascii //weight: 1
        $x_1_16 = "yahoo.com" ascii //weight: 1
        $x_1_17 = "smtp.mail.ru" ascii //weight: 1
        $x_1_18 = "smtp.google.com" ascii //weight: 1
        $x_1_19 = "smtp.aol.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 8 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_F_2147602380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.F"
        threat_id = "2147602380"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8c b5 b8 34 24 40 cd 9e 31 53 1c b4 f3 43 5a e6 fe 4c 4f 47 47 45 52 08 0b 4f 42 0b 73 c9 6b 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_F_2147602380_1
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.F"
        threat_id = "2147602380"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 8b c1 18 cc cc 08 cc 51 c7 dc 42 71 b8 44 23 40 00 8d 49 42 fa 01 42 f7 42 b2 1a 32 d2 83 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_H_2147605505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.H"
        threat_id = "2147605505"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 d6 24 9e 70 30 3e 48 d0 8e b8 38 1d 60 5c 02 55 09 da a6 28 65 6f a4 65 ee 1f 4c 4f 47 47 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_I_2147606944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.I"
        threat_id = "2147606944"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 f6 76 08 30 04 08 40 3b c6 72 f8 33 c0 85 f6 76 08 30 04 08 40 3b c6 72 f8 4a 75 e1}  //weight: 1, accuracy: High
        $x_1_2 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed be ?? ?? ?? ?? 8d 7d e8 a5 a5 a5 a5 b8 ?? ?? ?? ?? 8b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Spammer_Win32_Tedroo_J_2147607329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.J"
        threat_id = "2147607329"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 30 04 cb f8 4b 03 4a 75 e1 00 10 55 8b ec 51 51 8d 45 fc 50 ff 75 08 30 f8 50 6a 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_Q_2147608072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.Q"
        threat_id = "2147608072"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 e3 66 8b 45 14 6a 01 61 fe 61 ff d7 8b 4d 10 33 db 38 19 79 00 fc e1 89 b5 02 34 04 34 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_R_2147608877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.R"
        threat_id = "2147608877"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b e8 85 ed 74 57 53 56 f0 35 6f 10 1d 20 6a 30 68 04 21 c0 10 55 ff d6 8b 1d 50 14 1f f8 7b 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_S_2147609484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.S"
        threat_id = "2147609484"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b e8 85 ed 74 57 53 56 8b 35 08 69 57 6a 30 68 d0 39 55 ff d6 8b 1d 0c f2 f8 85 ff 74 11 8d 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_X_2147610856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.X"
        threat_id = "2147610856"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 30 04 cb f8 4b 03 4a 75 e1 03 ?? 81 ec 10 01 00 00 56 57 be ?? ?? ?? f4 a5 a5 66 a5 be ?? ?? 58 56 53 e8 ?? ?? c8 85 c0 59 59 74 5b 33 c0 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Tedroo_Z_2147613317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.Z"
        threat_id = "2147613317"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 14 13 3e 00 6a 00 6a 00 ff 15 24 20 3e 00 89 45 bc c7 45 e0 00 00 00 00 83 45 e0 01 c7 45 e4 01 00 00 00 83 45 e4 01 c7 45 e8 03 00 00 00 c7 45 ec 04 00 00 00 c7 45 f0 05 00 00 00 c7 45 f4 01 00 00 00 83 45 f4 05 c7 45 f8 07 00 00 00 c7 45 fc 01 00 00 00 83 45 fc 07 6a 08 8d 45 e0 50 8d 45 cc 50 e8 84 fd ff ff 83 c4 0c a1 0b b6 3e 00 c1 e8 02 50 68 00 30 3e 00 8d 45 cc 50 e8 6a fd ff ff}  //weight: 1, accuracy: High
        $x_2_2 = {a1 52 28 56 a4 78 b0 0d 60 e8 0d 70 f4 fd 72 52 0d 67 fc 38 f9 c7 28 d9 2f 14 40 42 62 56 5f 13 be de c3 f0 9c 93 31 6d 2b 46 64 d3 b6 b7 02 0d 11 a0 7b d0 19 ff 72 1d 1a 7e 94 f5 c1 9b bc 8d}  //weight: 2, accuracy: High
        $x_2_3 = {f7 a5 6c 38 6b b9 b1 23 b6 15 78 b2 b1 0f 44 59 8d c7 a3 31 f5 49 58 40 e9 83 a5 3e 1e 8c d5 63 66 c4 3c df a8 c4 ff 7b b3 d6 84 f8 27 b4 5c af 1b af 65 c8 6b cf 0b 42 00 44 d6 c3 77 b6 4d 46}  //weight: 2, accuracy: High
        $x_2_4 = {6f fb c8 1f 01 64 77 31 df 50 e9 a0 c4 82 9a 30 d1 03 97 38 d8 21 59 27 fc 28 3f dc 36 30 8f 2a c1 da 31 f2 2c b0 fd 96 f5 24 03 f4 99 2a 28 58 25 79 44 2d f1 6f ba ae 9c 2c 9b ea 28 de 8b 9a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_A_2147621081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.gen!A"
        threat_id = "2147621081"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 20 32 45 ff 47 88 04 33 b8 ?? ?? ?? ?? 8d 48 01 8a 10}  //weight: 3, accuracy: Low
        $x_3_2 = {57 bf 0d 00 00 00 01 7c 24 04 5f ff e7}  //weight: 3, accuracy: High
        $x_2_3 = {33 db 81 c3 7e 66 04 80}  //weight: 2, accuracy: High
        $x_2_4 = {8a d0 80 c2 54 30 14 01 40 3b c6 72 f3}  //weight: 2, accuracy: High
        $x_2_5 = {0f 01 0c 24 b8 00 00 00 00 0b 44 24 02 83 c4 08 3d 00 00 00 d0}  //weight: 2, accuracy: High
        $x_2_6 = "/spm/s_" ascii //weight: 2
        $x_2_7 = "SPM_NET" ascii //weight: 2
        $x_1_8 = "%s?ver=%d" ascii //weight: 1
        $x_1_9 = "$TO_EMAIL" ascii //weight: 1
        $x_1_10 = "_id.dat" ascii //weight: 1
        $x_1_11 = "do_work" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_AA_2147627493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.AA"
        threat_id = "2147627493"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a d0 80 c2 54 30 14 08 40 3b c6 72 f3}  //weight: 4, accuracy: High
        $x_1_2 = "$QM_MESSID" ascii //weight: 1
        $x_1_3 = "update%d%s" ascii //weight: 1
        $x_1_4 = "/spm/" ascii //weight: 1
        $x_1_5 = "_id.dat" ascii //weight: 1
        $x_1_6 = "</config>" ascii //weight: 1
        $x_1_7 = "$TO_EMAIL" ascii //weight: 1
        $x_1_8 = "&smtp=%s&task=%d" ascii //weight: 1
        $x_1_9 = "get_id.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_AB_2147628636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.AB"
        threat_id = "2147628636"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "id=%s&tick=%d&ver=%d&smtp=%s&task=%d" ascii //weight: 5
        $x_5_2 = "%s?ver=%d&id=%s&tick=%d&smtp=%s&task=%d" ascii //weight: 5
        $x_5_3 = "&errors[%d]=%d" ascii //weight: 5
        $x_2_4 = {32 32 30 00 48 45 4c 4f 20 25 73}  //weight: 2, accuracy: High
        $x_2_5 = "MAIL FROM: <%s>" ascii //weight: 2
        $x_2_6 = "RCPT TO: <%s>" ascii //weight: 2
        $x_1_7 = "@@FROM_EMAIL" ascii //weight: 1
        $x_1_8 = "@@FROM_NAME" ascii //weight: 1
        $x_1_9 = "@@MESSAGE_ID" ascii //weight: 1
        $x_1_10 = "@@BOUNDARY" ascii //weight: 1
        $x_1_11 = "$TO_%s" ascii //weight: 1
        $x_1_12 = "$QM_%s" ascii //weight: 1
        $x_2_13 = {33 c0 8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 83 f8 ?? 72 ef}  //weight: 2, accuracy: Low
        $x_2_14 = {33 c9 8b d0 2b 91 ?? ?? ?? ?? 81 fa 60 ea 00 00 76 0a c7 81 ?? ?? ?? ?? 02 00 00 00 83 c1 04 83 f9 14 7c de 06 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_B_2147629802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.gen!B"
        threat_id = "2147629802"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 1b 8b 55 fc 83 c2 54 8b 45 08 03 45 fc 0f be 08 33 ca}  //weight: 2, accuracy: High
        $x_2_2 = {74 08 66 c7 45 ?? bb 01 eb 06 66 c7 45 ?? 50 00 6a 01}  //weight: 2, accuracy: Low
        $x_2_3 = {83 c0 04 75 02 eb e4 66 c7 45 ?? 02 00 6a 35 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {0f be 02 83 f8 4d 75 5f 8b 8d ?? ?? ?? ?? 0f be 51 01 83 fa 5a 75 50}  //weight: 2, accuracy: Low
        $x_2_5 = {83 c2 20 33 c2 8b 4d ?? 03 4d}  //weight: 2, accuracy: Low
        $x_1_6 = {04 20 32 45 ff 47 88 ?? ?? b8 ?? ?? ?? ?? 8d 48 01 8a 10}  //weight: 1, accuracy: Low
        $x_1_7 = "/spm/" ascii //weight: 1
        $x_1_8 = "&smtp=%s&task=%d" ascii //weight: 1
        $x_1_9 = {63 6c 69 63 6b 3a 00}  //weight: 1, accuracy: High
        $x_1_10 = {72 75 6e 25 64 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Tedroo_AL_2147688249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Tedroo.AL"
        threat_id = "2147688249"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 00 2e 00 70 00 6c 00 20 00 50 00 65 00 72 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 70 00 6c 00 7c 00 2a 00 2e 00 74 00 78 00 74 00 20 00 54 00 65 00 78 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 74 00 78 00 74 00 7c 00 2a 00 2e 00 2a 00 20 00 41 00 6c 00 6c 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 72 00 64 00 2e 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_10_3 = {4d 00 61 00 69 00 6c 00 73 00 20 00 43 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 65 00 64 00 3a 00 20 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {55 00 52 00 4c 00 73 00 20 00 50 00 72 00 6f 00 73 00 65 00 73 00 73 00 65 00 64 00 3a 00 20 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

