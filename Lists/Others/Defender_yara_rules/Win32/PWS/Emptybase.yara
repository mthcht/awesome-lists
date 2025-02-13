rule PWS_Win32_Emptybase_A_2147605139_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Emptybase.A"
        threat_id = "2147605139"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Emptybase"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 44 24 10 75 e9 38 18 74 07 88 18 40 89 44 24 10 6a 04 68 ?? ?? 00 10 57 ff 15 ?? ?? 00 10 85 c0 75 03 83 c7 04}  //weight: 2, accuracy: Low
        $x_1_2 = {49 45 53 63 72 47 72 61 62 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 45 4d 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "Image\"; filename=\"screen.lzw\"" ascii //weight: 1
        $x_1_5 = {67 65 74 5f 75 72 6c 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Emptybase_B_2147630658_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Emptybase.B"
        threat_id = "2147630658"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Emptybase"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 44 ff 77 04 ff 77 0c 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 53 56 ff 75 f8 c6 06 47 c6 46 01 45 c6 46 02 54}  //weight: 1, accuracy: Low
        $x_1_2 = {75 54 8d 45 e0 50 ff 75 0c e8 ?? ?? ?? ?? 59 59 6a 06 8d 45 e0 50 ff 75 f4 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {55 70 64 61 74 65 00 00 53 74 6f 70 00 00 00 00 41 63 74 69 76 61 74 65 00 00 00 00 45 78 65 63 75 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

