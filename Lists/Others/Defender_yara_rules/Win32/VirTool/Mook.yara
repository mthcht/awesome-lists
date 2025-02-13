rule VirTool_Win32_Mook_A_2147605587_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Mook.gen!A"
        threat_id = "2147605587"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mook"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 6f 73 74 3a 20 77 77 77 2e 6d 79 73 65 78 77 65 62 2e 63 6f 6d [0-4] 77 77 77 2e 6d 79 73 65 78 77 65 62 2e 63 6f 6d [0-4] 43 6f 6e 74 65 6e 74 2d 74 79 70 65}  //weight: 5, accuracy: Low
        $x_5_2 = {48 6f 73 74 3a 20 77 77 77 2e 6d 79 73 65 78 77 65 62 2e 63 6f 6d [0-6] 43 6f 6e 74 65 6e 74 2d 74 79 70 65}  //weight: 5, accuracy: Low
        $x_5_3 = {77 77 77 2e 6d 79 73 65 78 77 65 62 2e 63 6f 6d [0-4] 50 4f 53 54 20 2f 6c 6f 67 65 72 2e 70 6f 73 74 2e 70 68 70 20 48 54 54 50 2f 31 2e 31}  //weight: 5, accuracy: Low
        $x_5_4 = {64 73 72 74 65 33 32 2e 64 6c 6c [0-2] 49 6e 73 74 61 6c 6c 48 6f 6f 6b [0-2] 4b 65 79 62 6f 61 72 64 50 72 6f 63 [0-2] 4d 6f 75 73 65 50 72 6f 63 [0-2] 55 6e 69 6e 73 74 61 6c 6c 48 6f 6f 6b}  //weight: 5, accuracy: Low
        $x_5_5 = {70 6f 72 74 65 33 32 2e 64 6c 6c [0-2] 49 6e 73 74 61 6c 6c 48 6f 6f 6b [0-2] 4b 65 79 62 6f 61 72 64 50 72 6f 63 [0-2] 4d 6f 75 73 65 50 72 6f 63 [0-2] 55 6e 69 6e 73 74 61 6c 6c 48 6f 6f 6b}  //weight: 5, accuracy: Low
        $x_20_6 = {8a 07 83 e0 0f bb [0-4] 03 d8 8a 0b 88 0e 46 8a 07 25 f0 00 00 00 c1 e8 04 bb [0-4] 03 d8 8a 0b 88 0e ff 4d fc 83 7d fc 00 74 04 47 46 eb cd}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

