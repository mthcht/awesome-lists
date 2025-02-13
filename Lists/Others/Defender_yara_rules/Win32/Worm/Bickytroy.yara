rule Worm_Win32_Bickytroy_2147608199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bickytroy"
        threat_id = "2147608199"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bickytroy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Autorun.Inf" ascii //weight: 1
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_5_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 54 72 69 63 6b 79 42 6f 79 2e 6d 73 69 0d 0a 00 43 3a 5c}  //weight: 5, accuracy: High
        $x_5_4 = {54 61 73 6b 4d 67 72 2e 65 78 65 00 5c 54 72 69 63 6b 79 42 6f 79 2e 65 78 65}  //weight: 5, accuracy: High
        $x_10_5 = {83 f8 03 74 13 83 f8 02 74 0e 83 f8 06 74 09 83 f8 04 0f 85 ?? ?? 00 00 80 3b 41 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

