rule Worm_Win32_FoxBlade_D_2147814023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/FoxBlade.D!dha"
        threat_id = "2147814023"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "FoxBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 6f 6d 61 6e 63 65 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = "& wevtutil cl System" ascii //weight: 2
        $x_2_3 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 72 65 67 73 76 72 33 32 20 2f 73 20 2f 69 20 2e 2e 5c 00}  //weight: 2, accuracy: High
        $x_2_4 = {5c 5c 25 73 5c 70 69 70 65 5c 25 73 [0-16] 4e 75 6c 6c 53 65 73 73 69 6f 6e 50 69 70 65 73}  //weight: 2, accuracy: Low
        $x_1_5 = {4e 54 4c 4d 75 ?? ?? ?? ?? 04 53 53 50 00 75}  //weight: 1, accuracy: Low
        $x_1_6 = {02 4e 54 20 ?? ?? 04 4c 4d 20 30 ?? ?? 08 2e 31 32 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_FoxBlade_E_2147814024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/FoxBlade.E!dha"
        threat_id = "2147814024"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "FoxBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 6a 41 58 6a 44 66 89 45 f0 8d 55 f0 58 6a 4d 8b 4e 08 66 89 45 f2 58 6a 49 66 89 45 f4 58 6a 4e 66 89 45 f6}  //weight: 1, accuracy: High
        $x_1_2 = "c%02X%02X%02X%02X%02X%02X" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

