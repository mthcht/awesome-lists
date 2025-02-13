rule Worm_Win32_Tercesph_2147607567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tercesph"
        threat_id = "2147607567"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tercesph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 00 65 00 63 00 72 00 65 00 74 00 5c 00 42 00 61 00 73 00 69 00 63 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 64 00 5c 00 57 00 6f 00 72 00 6d 00 2b 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 28 00 4e 00 45 00 57 00 [0-2] 29 00 5c 00 77 00 6f 00 72 00 6d 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_2 = {53 00 65 00 63 00 72 00 65 00 74 00 2e 00 65 00 78 00 65 00 00 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "shell\\open\\Command=Secret.exe" wide //weight: 1
        $x_1_4 = {50 00 68 00 69 00 6d 00 20 00 6e 00 67 00 75 00 6f 00 69 00 20 00 6c 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00 00 00 46 00 69 00 6c 00 65 00 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 6b 00 64 00 63 00 6f 00 6d 00 73 00 2e 00 64 00 6c 00 6c 00 ?? ?? ?? ?? ?? ?? 75 00 73 00 65 00 72 00 69 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

