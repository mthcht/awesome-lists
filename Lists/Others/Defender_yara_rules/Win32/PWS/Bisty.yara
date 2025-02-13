rule PWS_Win32_Bisty_A_2147646062_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bisty.A"
        threat_id = "2147646062"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bisty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7b 65 33 64 66 36 62 34 31 39 64 31 66 7d 43 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c}  //weight: 5, accuracy: Low
        $x_1_2 = "<Previous Track key>" ascii //weight: 1
        $x_2_3 = {4f 75 74 6c 6f 6f 6b 32 30 30 33 5f 49 4d 41 50 00 00 00 00 4f 75 74 6c 6f 6f 6b 32 30 30 32 5f 49 4d 41 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

