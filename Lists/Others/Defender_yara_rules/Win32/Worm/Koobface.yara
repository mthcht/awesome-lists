rule Worm_Win32_Koobface_A_127243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.gen!A"
        threat_id = "127243"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 54 41 52 54 4f 4e 43 45 00 [0-16] 25 73 5c 74 74 5f 25 64 2e 65 78 65 00}  //weight: 2, accuracy: Low
        $x_1_2 = {4c 49 4e 4b 54 45 58 54 5f 4d 00 [0-3] 54 45 58 54 5f 4d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 49 4e 4b 5f 4d 00 00 54 45 58 54 5f 4d 00}  //weight: 1, accuracy: High
        $x_1_4 = {d4 dc ff ff 68 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 83 c4 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_B_127250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.B"
        threat_id = "127250"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 24 33 f6 81 c6 60 ea 00 00 81 fe 80 8d 5b 00 0f 8f e4 00 00 00 56 ff 15 ?? ?? 40 00 e8 ?? ?? ff ff 84 c0 74 de}  //weight: 3, accuracy: Low
        $x_5_2 = {c6 00 73 c6 40 01 2d c6 40 02 6b c6 40 03 61 c6 40 04 6b c6 40 05 61 c6 40 06 2e c6 40 00 6e c6 40 08 65 c6 40 09 74 c3}  //weight: 5, accuracy: High
        $x_1_3 = "/friends/#view=everyone" ascii //weight: 1
        $x_1_4 = "/inbox/?compose&id=%s" ascii //weight: 1
        $x_1_5 = "Facebook |" wide //weight: 1
        $x_1_6 = "new.%s/profile.php?id=" wide //weight: 1
        $x_1_7 = "%s/profile.php?id=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_D_129668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.D"
        threat_id = "129668"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6d 61 72 6b 32 2e 64 61 74 00}  //weight: 4, accuracy: High
        $x_2_2 = {53 54 41 52 54 00 00 00 61 32 32 [0-4] 2e 63 6f 6d}  //weight: 2, accuracy: Low
        $x_2_3 = "nick=%s&login=%s&success" ascii //weight: 2
        $x_2_4 = "FBTARGETPERPOST" ascii //weight: 2
        $x_2_5 = {2f 66 62 2f 65 72 72 6f 72 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 66 61 63 25 73 6f 6b 2e 63 6f 6d 2f 00}  //weight: 2, accuracy: High
        $x_1_7 = {00 6d 79 73 70 61 63 65 2e 63 6f 6d 2f 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 65 6e 64 54 6f 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 25 73 2f 6d 61 69 6c 2f 4d 61 69 6c 43 6f 6d 70 6f 73 65 2e 6a 73 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_F_131698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.F"
        threat_id = "131698"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myspace.com/" ascii //weight: 1
        $x_1_2 = "fac%sok.com/" ascii //weight: 1
        $x_1_3 = "bebo.com/" ascii //weight: 1
        $x_1_4 = "Password" ascii //weight: 1
        $x_1_5 = "Use%sill%snd%sv:1.9.0.1) Gecko/2008070208 Firefox/3.0.1" ascii //weight: 1
        $x_1_6 = "muchomambo" ascii //weight: 1
        $x_10_7 = "autoturnedoff" ascii //weight: 10
        $x_10_8 = "http://www.%s/mail/MailCompose.jsp?ToMemberId=%s" ascii //weight: 10
        $x_10_9 = "nick=%s&login=%s&success=%d&friends=%d&captcha=%d&finish=%d&v=%s&p=%s&c=%d" ascii //weight: 10
        $x_10_10 = {6a 0a 33 d2 59 f7 f1 52 ff d6}  //weight: 10, accuracy: High
        $x_10_11 = {99 6a 3c 59 f7 f9 52 ff d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_G_132372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.G"
        threat_id = "132372"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "myspace.com" ascii //weight: 10
        $x_10_2 = "del \"%s\"" ascii //weight: 10
        $x_10_3 = "%s \"%s\" goto" ascii //weight: 10
        $x_10_4 = "%s\\ex_%d.exe" ascii //weight: 10
        $x_10_5 = "Use%sill%snd%sv" ascii //weight: 10
        $x_1_6 = "http://www.%s/MyFriends.jsp" ascii //weight: 1
        $x_1_7 = {72 65 67 65 64 69 74 20 2f 73 20 63 3a 5c [0-2] 2e 72 65 67}  //weight: 1, accuracy: Low
        $x_2_8 = "nick=%s&login=%s&success=%d&friends=%d&captcha=%d" ascii //weight: 2
        $x_1_9 = "UrlEscapeA" ascii //weight: 1
        $x_1_10 = "InternetGetConnectedState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_H_132994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.H"
        threat_id = "132994"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 10 2b 00 00 e8 ?? ?? ?? 00 55 56 ff 15 ?? ?? ?? 00 99 b9 0a 00 00 00 [0-16] f7 f9 [0-16] 52 ff d5}  //weight: 2, accuracy: Low
        $x_3_2 = {f2 ae f7 d1 49 03 d1 3b f2 72 bd ff 15 ?? ?? ?? ?? 33 d2 b9 0a 00 00 00 f7 f1 52 ff d5 5f 5b 5e 5d}  //weight: 3, accuracy: Low
        $x_3_3 = {56 ff d5 83 c4 04 33 ff 56 ff d5 83 c4 04 85 c0 0f 85 ?? ?? 00 00 47 81 ff 58 02 00 00 7c e9 56}  //weight: 3, accuracy: Low
        $x_1_4 = "%s/friends/?view=" ascii //weight: 1
        $x_1_5 = "recaptcha_image" ascii //weight: 1
        $x_1_6 = "captcha_submit" ascii //weight: 1
        $x_1_7 = "FBSHAREURL" ascii //weight: 1
        $x_1_8 = "FBTARGET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_I_134787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.I"
        threat_id = "134787"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c8 01 00 00 6a 01 ff d6 ff 4c 24 20 75 f6}  //weight: 3, accuracy: High
        $x_2_2 = "&ck=%d&c_fb=%d&c_ms=%d&c_hi=%d&c_be=%d&c_fr=%d&c_yb=%d" ascii //weight: 2
        $x_1_3 = "FBTARGETPERPOST" ascii //weight: 1
        $x_1_4 = "FBSHAREURL" ascii //weight: 1
        $x_1_5 = "#BLACKLABEL" ascii //weight: 1
        $x_1_6 = "%s\\tt_%d.exe" ascii //weight: 1
        $x_1_7 = "/achcheck.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_J_135256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.J"
        threat_id = "135256"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 7c 53 ff 15 ?? ?? ?? ?? 8b f0 83 c4 08 3b f5 0f 84 ?? ?? 00 00 68 ?? ?? ?? ?? c6 06 00 53 46 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 51 52 c7 44 24 24 3c 00 00 00 c7 44 24 38 63 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "nick=%s&login=%s&success=%d&friends=%d&captcha=%d&finish=%d&v=%s&p=%s&c=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_B_137851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.gen!B"
        threat_id = "137851"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 54 41 25 73 43 45 00 52 54 4f 4e [0-16] 25 73 5c 74 74 5f 25 64 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "&v=%s&c=%d&s=%s&l=%s" ascii //weight: 1
        $x_1_3 = {41 43 48 5f 4f 4b 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 67 65 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {36 46 31 33 7d 22 0a 22 45 78 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Koobface_C_140765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.gen!C"
        threat_id = "140765"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 0c 46 81 fe 10 27 00 00 7c c4 5e c9 c3}  //weight: 2, accuracy: High
        $x_1_2 = {8d 4d fc 6a 00 51 ff d0 85 c0 74 0a f6 45 fc 07 74 04 b0 01}  //weight: 1, accuracy: High
        $x_1_3 = {80 7c 30 ff 0d 59 75 0b 56 e8}  //weight: 1, accuracy: High
        $x_1_4 = {80 38 7c 75 03 89 45 1c}  //weight: 1, accuracy: High
        $x_1_5 = {54 49 25 73 5f 4d 00 00 54 4c 45 00 4c 25 73 5f}  //weight: 1, accuracy: High
        $x_1_6 = "ck=%d&c_fb=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_E_142251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.gen!E"
        threat_id = "142251"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "account secutiry" ascii //weight: 1
        $x_1_2 = "captcha incorrect" ascii //weight: 1
        $x_1_3 = "%s?act%sen&v=%s&ban_url" ascii //weight: 1
        $x_1_4 = "dump responce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Koobface_T_146300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.T"
        threat_id = "146300"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 73 79 73 2f 3f 61 63 74 69 6f 6e 3d 61 76 67 65 6e 26 76 3d 31 00}  //weight: 1, accuracy: High
        $x_1_2 = "<li>For Microsoft: <a href=" ascii //weight: 1
        $x_1_3 = {8b d8 83 fb ff 0f 84 ?? ?? 00 00 8d 44 24 ?? 50 53 ff 15 ?? ?? 40 00 8b e8 83 fd 0a 0f 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_U_147458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.U"
        threat_id = "147458"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&crc=%d" ascii //weight: 1
        $x_1_2 = "&c_be=%d&c_tg=%d&c_nl=%d&iedef=%d" ascii //weight: 1
        $x_1_3 = "&c_fb=%d&c_ms=%d&c_hi=%d&c_tw=%d" ascii //weight: 1
        $x_1_4 = "CLSID\\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}" ascii //weight: 1
        $x_1_5 = "http\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_F_147883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.gen!F"
        threat_id = "147883"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 85 38 ff ff ff c6 85 38 ff ff ff 6d 50 c6 85 39 ff ff ff 59 c6 85 3a ff ff ff 73 c6 85 3b ff ff ff 70 c6 85 3c ff ff ff 41 c6 85 3d ff ff ff 43 c6 85 3e ff ff ff 45 c6 85 3f ff ff ff 2e c6 85 40 ff ff ff 43 c6 85 41 ff ff ff 4f c6 85 42 ff ff ff 4d ff 15 ?? ?? ?? ?? 6a 63 8d 85 d4 fe ff ff 6a 00 50 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 4d fc 6a 00 51 ff d0 85 c0 74 0a f6 45 fc 07 74 04 b0 01}  //weight: 10, accuracy: High
        $x_1_3 = "readyState" wide //weight: 1
        $x_1_4 = "%sW%sros%sow%srentVer%sun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_G_155318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.gen!G"
        threat_id = "155318"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?action=ppgen&a=%d&v=%s&pid=%s&cnt=%d" ascii //weight: 1
        $x_1_2 = "%s?action=md5gen&url=%s&reqhash=%s&reshash=%s&v=01" ascii //weight: 1
        $x_1_3 = "%s?v=1&action=passgen&l=%s&p=%s" ascii //weight: 1
        $x_1_4 = "%s?action=banurlgen&v=%s&ban_url=%s" ascii //weight: 1
        $x_1_5 = "%s\\zpskon_%d.exe" ascii //weight: 1
        $x_1_6 = {66 65 65 64 77 61 6c 6c 5f 77 69 74 68 5f 63 6f 6d 70 6f 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 00 72 00 6f 00 61 00 64 00 62 00 6c 00 6f 00 63 00 6b 00 2f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Koobface_AP_156823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.AP"
        threat_id = "156823"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 f8 00 00 00 aa f4 28 6b ?? ?? b1}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 b8 00 fc 0d}  //weight: 1, accuracy: High
        $x_1_3 = {f5 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\NuAT.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_AT_159940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.AT"
        threat_id = "159940"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 38 ff ff ff 41 43 45 2e c7 85 34 ff ff ff 6d 59 73 70 66 c7 85 3c ff ff ff 43 4f c6 85 3e ff ff ff 4d}  //weight: 1, accuracy: High
        $x_1_2 = {8a 55 f7 30 11 41 38 19 75 f6 80 38 31 75 02 b3 01}  //weight: 1, accuracy: High
        $x_1_3 = {63 61 70 74 63 68 61 20 66 69 6e 69 73 68 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_AU_161715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.AU"
        threat_id = "161715"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?action=twreg&mode=res&" ascii //weight: 1
        $x_1_2 = {2f 2e 73 79 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 88 13 00 00 c6 45 fc 0f ff d7 53 8d 85 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Koobface_AV_161995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.AV"
        threat_id = "161995"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/.sys.php" ascii //weight: 2
        $x_2_2 = "scan domain attempt" ascii //weight: 2
        $x_1_3 = "Yahoo mlogin begin" ascii //weight: 1
        $x_1_4 = "form[id]" ascii //weight: 1
        $x_1_5 = "CreateIE 2 begin" ascii //weight: 1
        $x_1_6 = "crypted code detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_AW_164885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.AW"
        threat_id = "164885"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c6 50 c3 00 00 81 fe a0 25 26 00 0f 8f ?? ?? 00 00 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 de}  //weight: 2, accuracy: Low
        $x_1_2 = "dump responce ==" ascii //weight: 1
        $x_1_3 = "#BLUELABEL" ascii //weight: 1
        $x_1_4 = "%s?a%sn=%sgen&v=%s" ascii //weight: 1
        $x_1_5 = {25 73 3f 61 63 74 69 6f 6e 3d [0-10] 26 68 61 72 64 69 64 3d 25 73 26 76 3d 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Koobface_AX_167280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Koobface.AX"
        threat_id = "167280"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/.sys.php" ascii //weight: 2
        $x_1_2 = "%s?a%sn=%sgen&v=%s" ascii //weight: 1
        $x_1_3 = "CreateIE 2 begin" ascii //weight: 1
        $x_1_4 = "crypted code detected" ascii //weight: 1
        $x_1_5 = "dump responce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

