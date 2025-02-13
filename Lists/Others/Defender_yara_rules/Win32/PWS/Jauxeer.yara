rule PWS_Win32_Jauxeer_A_2147604726_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jauxeer.A"
        threat_id = "2147604726"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jauxeer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 8d a2 fb ff ff 0f b7 95 aa fb ff ff 8b c1 8d 8d b0 fd ff ff 03 c0 8d 04 80 03 d0 42 52 8d 95 b0 fe ff ff 52 68 ?? ?? 44 00 51 e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "\\Recycled" ascii //weight: 1
        $x_1_3 = "%s\\%d%d.dat" ascii //weight: 1
        $x_1_4 = "rundll32.exe %s s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Jauxeer_A_2147604726_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jauxeer.A"
        threat_id = "2147604726"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jauxeer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 01 00 00 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 45 fc 39 30 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f8 03 75}  //weight: 5, accuracy: Low
        $x_3_2 = {2b 45 dc 3d 10 27 00 00 0f 87}  //weight: 3, accuracy: High
        $x_2_3 = "&ver=%s&tgid=%s&address=%s" ascii //weight: 2
        $x_1_4 = {65 3a 00 45 3a 5c 00 25 2e 38 78 25 2e 38 78 25}  //weight: 1, accuracy: High
        $x_1_5 = {33 36 30 73 61 66 65 00 5c 33 36 30 5c}  //weight: 1, accuracy: High
        $x_1_6 = {6f 6c 6c 79 64 62 67 2e 69 6e 69 00 4c 69 62 63}  //weight: 1, accuracy: High
        $x_1_7 = {2d 4c 65 6e 67 74 68 3a 00 0d 0a 00 25 64 00 43 3a 5c}  //weight: 1, accuracy: High
        $x_1_8 = {3c 2f 25 73 3e 00 3f 43 49 44 3d}  //weight: 1, accuracy: High
        $x_1_9 = {2e 61 73 70 00 72 62 00 4d 5a 00}  //weight: 1, accuracy: High
        $x_1_10 = {77 62 2b 00 5b 56 45 52 5d}  //weight: 1, accuracy: High
        $x_1_11 = {5b 43 49 44 5d 00 53 6f 66 74 77 61 72 65}  //weight: 1, accuracy: High
        $x_1_12 = "f=%s&m=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

