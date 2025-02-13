rule Spammer_Win32_Emotet_A_2147690659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.A"
        threat_id = "2147690659"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://likesomessfortelr.eu/mSsNX3JDSJD/inNSj398LSj/" ascii //weight: 1
        $x_1_2 = "http://ajeyftrjqeashgda.mobi/mSsQDIMIQ/inIDw/" ascii //weight: 1
        $x_1_3 = "http://qwuyegasd3edarq6yu.org/mSsQDIMIQ/ind7694GDs/" ascii //weight: 1
        $x_1_4 = "cryspellingslaveseducation.eu/m39kNSJJ/i73yDJnjde/" ascii //weight: 1
        $x_1_5 = "http://bardubar.com/mMS83JIdhq/ieygBSH38hsJa/" ascii //weight: 1
        $x_1_6 = {8b 46 08 8b 56 04 8b 7c 24 10 8d 4c 24 08 51 8b 0e 2b d0 52 8b 97 44 02 00 00 03 c8 51 52 ff 15 ?? ?? ?? ?? 85 c0 74 29}  //weight: 1, accuracy: Low
        $x_10_7 = "del /Q /F \"%S\"" ascii //weight: 10
        $x_10_8 = "%s\\_tmpxqr.bat" wide //weight: 10
        $x_10_9 = "my huge entropy for rng.. blah" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Emotet_B_2147692103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.B"
        threat_id = "2147692103"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "my huge entropy for rng.. blah" ascii //weight: 100
        $x_10_2 = "\"%s\" /c \"%s\"" wide //weight: 10
        $x_10_3 = "ComSpec" wide //weight: 10
        $x_1_4 = "%from_email%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Emotet_C_2147692416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.C"
        threat_id = "2147692416"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {0f b6 4d 0b 8d 34 01 8a 16 00 55 ff 0f b6 4d ff 03 c8 8a 19 fe 45 0b 88 1e 88 11 8b 4d 0c 0f b6 d2 0f b6 f3 03 f2 81 e6 ff 00 00 00 8a 14 06 03 cf 30 11 47 3b 7d 10 72 c7}  //weight: 100, accuracy: High
        $x_100_2 = "Av static entropy Microsoft Essential .... oh oh oh" ascii //weight: 100
        $x_10_3 = "\"%s\" /c \"%s\"" wide //weight: 10
        $x_10_4 = "ComSpec" wide //weight: 10
        $x_1_5 = "%from_email%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Emotet_D_2147692802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.D"
        threat_id = "2147692802"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 48 33 d2 8b cf 2b f7 58 8a 1c 0e 32 9a ?? ?? ?? ?? 42 88 19 83 fa 09 72 02 33 d2 41 48 75 e9}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 cb 8d 3c 31 8a 0f 02 d1 88 54 24 ?? 0f b6 d2 8d 2c 32 8a 55 00 88 17 8b 7c 24 ?? 88 4d 00 0f b6 d2 0f b6 c9 03 d1 81 e2 ff 00 00 00 0f b6 14 32 30 14 38 40 fe c3 3b 44 24 ?? 72 be}  //weight: 10, accuracy: Low
        $x_10_3 = {0f b6 00 0f b6 4d ff 0f b6 55 f7 03 ca 81 e1 ff 00 00 00 8b 55 f8 0f b6 0c 0a 33 c1 8b 4d 0c 03 4d f0 88 01 e9 6b ff ff ff}  //weight: 10, accuracy: High
        $x_10_4 = {8b 45 08 03 45 f8 0f b6 08 8b 55 f4 0f b6 82 10 00 54 00 33 c8 8b 55 fc 03 55 f8 88 0a 8b 45 f4 83 c0 01 89 45 f4 83 7d f4 09 72 07 c7 45 f4 00 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {03 c1 25 ff 00 00 00 8b 4d ?? 0f b6 04 01 33 d0 8b 4d 0c 03 4d ?? 88 11 e9}  //weight: 10, accuracy: Low
        $x_10_6 = "\"%s\" /c \"%s\"" wide //weight: 10
        $x_10_7 = "ComSpec" wide //weight: 10
        $x_1_8 = "%from_email%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Emotet_F_2147696125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.F"
        threat_id = "2147696125"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<emailname><name><![CDATA[%s]" ascii //weight: 1
        $x_1_2 = "{\\*\\htmltag" ascii //weight: 1
        $x_2_3 = {85 c0 74 24 81 be ?? ?? 00 00 c8 00 00 00 75 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Emotet_G_2147696188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.G"
        threat_id = "2147696188"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<emailname><name><![CDATA[%s]" ascii //weight: 1
        $x_1_2 = "{\\*\\htmltag" ascii //weight: 1
        $x_1_3 = "<OutgoingLoginName><![CDATA[%s]]>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Emotet_H_2147697088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emotet.H"
        threat_id = "2147697088"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot_id=%s_name_path=%s" ascii //weight: 1
        $x_1_2 = "/input/in/go.php" ascii //weight: 1
        $x_1_3 = {7b 5c 2a 5c 68 74 6d 6c 74 61 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {3c 65 6d 61 69 6c 3e 3c 21 5b 43 44 41 54 41 5b 00}  //weight: 1, accuracy: High
        $x_1_5 = "<IncomingServer><![CDATA[%s]]></I" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

