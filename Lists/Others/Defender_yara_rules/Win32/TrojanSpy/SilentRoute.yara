rule TrojanSpy_Win32_SilentRoute_A_2147944484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SilentRoute.A"
        threat_id = "2147944484"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SilentRoute"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 37 00 33 00 76 00 67 00 7a 00 65 00 72 00 33 00 39 00 37 00 66 00 79 00 74 00 62 00 7a 00 75 00 6a 00 71 00 6f 00 6e 00 34 00 63 00 78 00 ?? ?? 6b 00 67 00 74 00 75 00 6a 00 34 00 33 00 67 00 68 00 39 00 6a 00 61 00 37 00 66 00 7a 00 7a 00 69 00 62 00 69 00 62 00 35 00 33 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 69 00 73 00 20 00 63 00 6c 00 69 00 63 00 6b 00 65 00 64 00 2c 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 ?? ?? 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 77 00 69 00 74 00 68 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {41 75 74 68 52 ?? 6d 6f 74 65 00 53 54 41 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

