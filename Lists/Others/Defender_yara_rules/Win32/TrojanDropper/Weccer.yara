rule TrojanDropper_Win32_Weccer_A_2147583028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Weccer.gen!A"
        threat_id = "2147583028"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Weccer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Objects\\{BA12780E-B91E-41A7-A51A-528CBD64284E" ascii //weight: 2
        $x_2_2 = "Objects\\{4136F291-C429-49C1-9B08-4B9C9DE4DEB6" ascii //weight: 2
        $x_2_3 = "Objects\\{E89097ED-3400-411D-9647-D368C3311C98" ascii //weight: 2
        $x_2_4 = "EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B" ascii //weight: 2
        $x_2_5 = "AD384045-470B-41c9-B4C6-5A4C7C3D43DC" ascii //weight: 2
        $x_2_6 = "BFE6CD43-1152-435a-8676-C2545D84BCF8" ascii //weight: 2
        $x_2_7 = "CLSID = s '{E89097ED-3400-411D-9647-D368C3311C98" ascii //weight: 2
        $x_2_8 = "CLSID = s '{60F4F2F3-0AFB-4AEF-B21E-B03D1C95B49E" ascii //weight: 2
        $x_2_9 = "ForceRemove {E89097ED-3400-411D-9647-D368C3311C98} = s 'IExplorerHelper Class" ascii //weight: 2
        $x_2_10 = "ForceRemove {60F4F2F3-0AFB-4AEF-B21E-B03D1C95B49E} = s 'BrowserHook Class" ascii //weight: 2
        $x_2_11 = "TypeLib' = s '{2215C65C-89E2-4363-820A-8C46FD4A9C97" ascii //weight: 2
        $x_3_12 = "http://zopabora.info/ssoft/softadmin.php" ascii //weight: 3
        $x_3_13 = {68 74 74 70 3a 2f 2f [0-16] 2e 62 69 7a 2f 61 64 6d 69 6e 73 73 63 72 69 70 74 2f 73 6f 66 74 61 64 6d 69 6e 2e 70 68 70}  //weight: 3, accuracy: Low
        $x_2_14 = {7b 45 41 42 32 32 41 43 33 2d 33 30 43 31 2d 31 31 43 46 2d 41 37 45 42 2d 30 30 30 30 43 30 35 42 41 45 30 42 7d [0-4] 63 6c 69 63 6b 65 64 26 75 72 6c 3d}  //weight: 2, accuracy: Low
        $x_3_15 = {62 6f 74 5f 69 6e 73 74 61 6c 6c 65 64 [0-5] 62 6f 74 5f 69 6e 73 74 61 6c 6c 65 64 26 69 64 3d 25 73 [0-4] 69 6e 73 74 61 6c 6c 69 6e 66 6f}  //weight: 3, accuracy: Low
        $x_6_16 = {67 65 74 5f 66 65 65 64 00 00 00 00 67 65 74 5f 6b 65 79 77 6f 72 64 00 79 65 73 00 63 61 6e 5f 63 6c 69 63 6b}  //weight: 6, accuracy: High
        $x_3_17 = {67 65 74 5f 32 65 78 65 63 75 74 65 [0-16] 72 65 67 69 73 74 65 72 [0-16] 68 74 74 70 3a 2f 2f 7a 6f 70 61 62 6f 72 61 2e 69 6e 66 6f}  //weight: 3, accuracy: Low
        $x_2_18 = {61 63 74 69 6f 6e 3d 25 73 26 76 65 72 3d 25 73 26 69 64 3d 25 73 [0-16] 76 30 2e 30 30 35 [0-4] 25 64 25 64 25 64 25 64 25 64 2e 25 73 [0-16] 53 74 61 72 74 20 50 61 67 65}  //weight: 2, accuracy: Low
        $x_2_19 = "C:\\InjectedCode.part0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_2_*))) or
            ((1 of ($x_3_*) and 10 of ($x_2_*))) or
            ((2 of ($x_3_*) and 8 of ($x_2_*))) or
            ((3 of ($x_3_*) and 7 of ($x_2_*))) or
            ((4 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 8 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

