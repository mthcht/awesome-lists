rule PWS_Win32_Divacol_A_2147647510_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Divacol.A"
        threat_id = "2147647510"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Divacol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 64 69 76 69 63 74 6f 72 79 2e 64 61 74 [0-16] 5c 68 61 6c 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {44 4f 4d 41 49 4e 20 3d [0-16] 50 41 53 53 57 4f 52 44 20 3d [0-16] 4e 41 4d 45 20 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

