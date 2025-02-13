rule Backdoor_Win32_Bazarloader_ST_2147767138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bazarloader.ST!!Bazarloader.ST"
        threat_id = "2147767138"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazarloader"
        severity = "Critical"
        info = "Bazarloader: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {05 62 61 7a 61 72 00}  //weight: 3, accuracy: High
        $x_3_2 = {2e 62 61 7a 61 72 00}  //weight: 3, accuracy: High
        $x_3_3 = {2e 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00}  //weight: 3, accuracy: High
        $x_3_4 = {77 73 32 5f 33 32 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c}  //weight: 3, accuracy: High
        $x_1_5 = {b9 49 f7 02 78 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 58 a4 53 e5 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_7 = {b9 10 e1 8a c3 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_8 = {b9 af b1 5c 94 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_9 = {b9 33 00 9e 95 [0-8] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

