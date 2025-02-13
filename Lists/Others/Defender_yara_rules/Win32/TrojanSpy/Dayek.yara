rule TrojanSpy_Win32_Dayek_A_2147652828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dayek.A"
        threat_id = "2147652828"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dayek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e2 01 83 fa 01 75 15 c7 45 fc 06 00 00 00 ba ?? ?? ?? ?? 8d 4d ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "adkey.php" wide //weight: 1
        $x_2_3 = {4d 61 69 6e 45 78 00 00 47 65 74 4c 6f 67 73 00 50 72 6f 4d 61 6e 00 00 48 54 54 50 43 6c 61 73 73 00 00 00 52 65 64 4d 6f 64 00}  //weight: 2, accuracy: High
        $x_2_4 = "\\UpdateEx\\UpdateEx.vbp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

