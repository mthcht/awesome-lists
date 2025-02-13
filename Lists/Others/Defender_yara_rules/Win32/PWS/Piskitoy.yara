rule PWS_Win32_Piskitoy_A_2147668119_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Piskitoy.A"
        threat_id = "2147668119"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Piskitoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d7 00 00 00 8d 49 00 56 33 db ff 15 ?? ?? ?? ?? b9 01 80 ff ff 66 3b c1 0f 85 ?? 00 00 00 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 03 8d 49 00 8b c5 8d 70 01 8a 10 40 84 d2 75 f9 2b c6 2b c1 8a 54 28 ff 8b c5 88 54 0c ?? 41 8d 70 01 8b ff 8a 10 40 84 d2}  //weight: 1, accuracy: Low
        $x_2_3 = {43 3a 5c 5c 57 49 4e 44 4f 57 53 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 43 61 74 52 6f 6f 74 32 5c 5c 7b 08 00 2d 04 00 2d 04 00 2d 04 00 2d 0c 00 7d 5c 5c 73 79 73 63 6f 6e 66 69 67 2e 64 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

