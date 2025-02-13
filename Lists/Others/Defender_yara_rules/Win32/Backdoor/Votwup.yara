rule Backdoor_Win32_Votwup_A_2147621288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Votwup.A"
        threat_id = "2147621288"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Votwup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 25 8d 45 f8 50 8b 45 fc e8 ?? ?? ff ff 8b c8 ba 05 00 00 00 8b 45 fc e8 ?? ?? ff ff b2 01 8b 45 f8 e8 ?? ?? ff ff 68 60 ea 00 00 e8 ?? ?? ff ff e9}  //weight: 5, accuracy: Low
        $x_2_2 = "/getcmd.php" ascii //weight: 2
        $x_2_3 = "/newbot.php" ascii //weight: 2
        $x_2_4 = "?uid=" ascii //weight: 2
        $x_1_5 = {77 74 66 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 64 31 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 64 32 00}  //weight: 1, accuracy: High
        $x_1_8 = {75 70 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Votwup_B_2147627019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Votwup.B"
        threat_id = "2147627019"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Votwup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {80 fb 3b 75 48 8d 45 f0 50 8b 45 f4 e8}  //weight: 3, accuracy: High
        $x_3_2 = {68 88 13 00 00 68 1c 80 00 00 56 6a 00 68 00 80 00 00}  //weight: 3, accuracy: High
        $x_1_3 = {3f 75 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 64 31 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {80 78 03 79 75 46}  //weight: 1, accuracy: High
        $x_1_7 = {64 64 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {64 64 74 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Votwup_D_2147649367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Votwup.D"
        threat_id = "2147649367"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Votwup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "result.dark" ascii //weight: 1
        $x_1_2 = "TERMSRV/*" ascii //weight: 1
        $x_1_3 = {3f 75 69 64 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 76 65 72 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {62 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 43 52 55 53 48 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f 00 64 61 72 6b 6e 65 73 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

