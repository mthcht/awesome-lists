rule HackTool_Win32_Donkaykay_I_2147933572_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Donkaykay.I!dha"
        threat_id = "2147933572"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Donkaykay"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5b 2b 5d 20 53 49 44 3a 25 64 2c 20 53 74 61 72 74 20 54 72 61 6e 73 6d 69 74 20 28 43 6f 6e 6e 65 63 74 53 6f 63 6b 65 74 20 3c 2d 3e 20 54 72 61 6e 73 6d 69 74 53 6f 63 6b 65 74 29 20 2e 2e 2e 2e 2e 2e (00|0a|0d)}  //weight: 2, accuracy: Low
        $x_1_2 = {5b 2d 5d 20 53 49 44 3a 25 64 2c 20 54 72 61 6e 73 6d 69 74 2c 20 52 65 63 65 69 76 65 20 64 61 74 61 20 66 61 69 6c 65 64 20 25 64 2e (00|0a|0d)}  //weight: 1, accuracy: Low
        $x_1_3 = {56 65 73 69 6f 6e 20 32 2e 30 (00|0a|0d)}  //weight: 1, accuracy: Low
        $x_1_4 = {56 65 73 69 6f 6e 20 31 2e 30 (00|0a|0d)}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 00 2b 00 5d 00 20 00 57 00 61 00 69 00 74 00 69 00 6e 00 67 00 20 00 66 00 6f 00 72 00 20 00 55 00 73 00 65 00 72 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 6f 00 6e 00 20 00 70 00 6f 00 72 00 74 00 3a 00 25 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5b 00 2b 00 5d 00 20 00 57 00 61 00 69 00 74 00 69 00 6e 00 67 00 20 00 66 00 6f 00 72 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 6f 00 6e 00 20 00 70 00 6f 00 72 00 74 00 3a 00 25 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

