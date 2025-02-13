rule Trojan_Win32_Cuffahlt_B_2147706386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cuffahlt.B"
        threat_id = "2147706386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cuffahlt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d [0-16] 00 4d 49 49 45 70 51 49 42 41 41 4b 43 41 51 45 41 79 6b 73 49 62 2b 79 4c 59 48 66 72 67 44 51 75}  //weight: 2, accuracy: Low
        $x_1_2 = "SELECT * FROM Win32_BaseBoard" ascii //weight: 1
        $x_1_3 = "cmd.exe /C ipconaei" ascii //weight: 1
        $x_1_4 = {43 65 72 74 73 46 46 2e 64 61 74 00 43 65 72 74 73 4f 50 2e 64 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cuffahlt_C_2147708727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cuffahlt.C"
        threat_id = "2147708727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cuffahlt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 65 6d 33 c7 44 24 ?? 32 5c 64 72 c7 44 24 ?? 69 76 65 72 c7 44 24 ?? 73 5c 65 74 c7 44 24 ?? 63 5c 68 6f c7 44 24 ?? 73 74 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 72 69 76 c7 44 24 ?? 65 72 73 5c c7 44 24 ?? 65 74 63 5c c7 44 24 ?? 68 6f 73 74 66 c7 44 24 ?? 73 00}  //weight: 1, accuracy: Low
        $x_2_3 = {66 69 67 20 c7 84 24 ?? ?? ?? ?? 2f 66 6c 75 c7 84 24 ?? ?? ?? ?? 73 68 64 6e 66 c7 84 24 ?? ?? ?? ?? 73 00}  //weight: 2, accuracy: Low
        $x_2_4 = {5c 64 6e 73 c7 45 ?? 61 70 69 2e c7 45 ?? 64 6c 6c 00 c7 45 ?? 5c 64 6c 6c c7 45 ?? 63 61 63 68 66 c7 45 ?? 65 00}  //weight: 2, accuracy: Low
        $x_2_5 = {6e 5c 52 75 c7 45 ?? 6e 6f 6e 63 66 c7 45 ?? 65 00 c7 45 ?? 63 6d 64 72 66 c7 45 ?? 75 6e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

