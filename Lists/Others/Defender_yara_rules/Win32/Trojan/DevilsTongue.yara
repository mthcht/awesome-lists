rule Trojan_Win32_DevilsTongue_A_2147784976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DevilsTongue.A!dha"
        threat_id = "2147784976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DevilsTongue"
        severity = "3"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 79 6d 49 6e 69 74 69 61 6c 69 7a 65 [0-4] 64 62 67 68 65 6c 70 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_2 = {64 00 62 00 67 00 48 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00 [0-4] 53 74 61 63 6b 57 61 6c 6b 36 34}  //weight: 2, accuracy: Low
        $x_1_3 = "windows.old\\windows" wide //weight: 1
        $x_3_4 = {8b 29 ee ed bd d3 cf bb 35 66 6c 63 3f ca ae 4a}  //weight: 3, accuracy: High
        $x_1_5 = "SMNew.dll" ascii //weight: 1
        $x_2_6 = {b8 ff 15 00 00 66 39 41 fa 74 06 80 79 fb e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

