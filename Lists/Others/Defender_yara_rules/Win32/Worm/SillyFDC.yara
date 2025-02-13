rule Worm_Win32_SillyFDC_2147597664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyFDC"
        threat_id = "2147597664"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyFDC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 73 6d 69 63 72 63 6f 2e 73 63 72 00 00 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32}  //weight: 2, accuracy: High
        $x_2_2 = "www.hotsword.com/fasoo.exe" ascii //weight: 2
        $x_1_3 = "\\autorun .inf" ascii //weight: 1
        $x_1_4 = "[AutoRun]" ascii //weight: 1
        $x_1_5 = "shell\\Auto\\command=" ascii //weight: 1
        $x_1_6 = "shellexecute=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyFDC_2147597664_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyFDC"
        threat_id = "2147597664"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyFDC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IM NOT THE ONLY ONE" ascii //weight: 1
        $x_2_2 = {25 63 3a 00 63 6f 70 79 5f 72 65 6d 6f 76 61 62 6c 65 3a 20 63 61 6e 6e 6f 74 20 67 65 74 20 76 6f 6c 75 6d 65 20 69 6e 66 6f 0a 00 25 75 2d 25 73 00 25 73 5c 6b 72 61 67}  //weight: 2, accuracy: High
        $x_2_3 = {64 6f 6e 65 00 6b 72 61 67 64 6f 72 2e 6c 6f 67 00 66 6f 75 6e 64 5f 72 65 6d 6f 76 61 62 6c 65 21 00 43 4f 50 59 49 4e 47 00 00 5c 6b 72 61 67 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 6b 72 61 67 00 25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 5b 41 75 74 6f 52 75 6e 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

