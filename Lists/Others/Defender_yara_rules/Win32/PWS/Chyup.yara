rule PWS_Win32_Chyup_A_2147628247_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Chyup.A"
        threat_id = "2147628247"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Chyup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ff_b.id = \"YuPi55\";" ascii //weight: 2
        $x_2_2 = {3f 67 65 74 3d 03 06 04 04 69 66 72 61 6d 65 74 61 73 6b 6c 69 6e 6b}  //weight: 2, accuracy: Low
        $x_1_3 = {3f 73 65 6e 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 31 00 00 ff ff ff ff 01 00 00 00 3a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Chyup_B_2147629614_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Chyup.B"
        threat_id = "2147629614"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Chyup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 7c 02 ff 7c 75 17 8b 45 fc e8}  //weight: 2, accuracy: High
        $x_1_2 = "&opt=ftp" ascii //weight: 1
        $x_1_3 = "&opt=grab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Chyup_C_2147647383_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Chyup.C"
        threat_id = "2147647383"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Chyup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 7c 02 ff 7c 75 17 8b 45 fc e8}  //weight: 2, accuracy: High
        $x_1_2 = {89 3e 8b d6 83 c2 05 8b c3 e8 ?? ?? ?? ?? 8b d6 83 c2 04 88 02 c6 03 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {66 ba d2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

