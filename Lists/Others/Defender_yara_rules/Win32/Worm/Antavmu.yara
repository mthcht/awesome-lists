rule Worm_Win32_Antavmu_A_2147629396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Antavmu.gen!A"
        threat_id = "2147629396"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Antavmu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 8b ce f7 f9 8b 4d 08 8a 84 15 ?? ?? ?? ?? 32 04 39 ff 45 fc 88 07 8b 45 fc 3b 45 10 7c}  //weight: 1, accuracy: Low
        $x_2_2 = {4e 45 57 20 49 4e 46 45 43 54 49 4f 4e 3a ?? 20 49 20 67 6f 74 20 69 6e 66 65 63 74 65 64 20 66 72 6f 6d 20 52 45 4d 4f 56 41 42 4c 45 20 44 45 56 49 43 45 2e 00}  //weight: 2, accuracy: Low
        $x_1_3 = "[nurotua]" ascii //weight: 1
        $x_2_4 = {00 5c 5c 2e 5c 62 6c 7a 62 6c 7a 62 6c 7a 00 00 00 5c 64 72 69 76 65 72 73 5c 62 6c 7a 62 6c 7a 62 6c 7a 2e 73 79 73 00}  //weight: 2, accuracy: High
        $x_1_5 = {2a 56 49 52 54 55 41 4c 2a 00 00 00 2a 56 42 4f 58 2a 00 00 2a 56 4d 57 41 52 45 2a 00 00 00 00 53 62 69 65 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4c 34 46 2d 4c 65 66 74 34 44 65 61 64 2d 4f 6e 6c 69 6e 65 2d 43 72 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = "hijacked removable drive from other bot" ascii //weight: 1
        $x_2_8 = {00 5c 62 6c 61 7a 65 77 72 6d 2e 76 6d 78 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

