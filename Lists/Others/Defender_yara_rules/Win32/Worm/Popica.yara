rule Worm_Win32_Popica_A_2147624345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Popica.gen!A"
        threat_id = "2147624345"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Popica"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 45 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 00 00 55 73 65 72 69 6e 69 74 00 00 00 00 73 79 73 74 65 6d 33 32 5c 63 74 66 6d 6f 6d 2e 65 78 65 00 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 63 74 66 6d 6f 6d 00 00 73 79 73 74 65 6d 33 32 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 00 00 00 45 78 70 6c 6f 72 65 72 00 00 00 00 65 78 70 6c 6f 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

