rule Ransom_Win32_Devman_A_2147944166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Devman.A"
        threat_id = "2147944166"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Devman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 84 24 f8 00 00 00 78 63 72 79 c7 84 24 fc 00 00 00 64 74 65 64 c7 84 24 00 01 00 00 6e 6f 74 73 c7 84 24 04 01 ?? 00 74 69 6c 6c c7 84 24 08 01 00 00 5f 61 6d 61 c7 84 24 0c 01 00 00 7a 69 6e 67 c7 84 24 10 01 00 00 67 5f 74 69 c7 84 24 14 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 21 5d 20 4c 44 41 50 20 6d 6f 64 65 20 72 65 71 75 69 72 65 73 20 75 73 65 72 6e 61 6d 65 20 61 6e 64 20 70 61 73 73 77 6f 72 64 2e 20 55 73 65 20 2d 75 20 61 6e 64 20 2d 70 20 66 6c 61 67 73 2e ?? ?? 5b 2b 5d 20 73 63 61 6e 6e 69 6e 67 20 66 6f 72 20 6c 69 76 65 20 68 6f 73 74 73 ?? ?? ?? ?? ?? 5b 2b 5d 20 74 65 72 6d 69 6e 61 74 69 6e 67 20 70 72 6f 63 65 73 73 65 73 ?? ?? ?? 5b 2b 5d 20 65 6e 63 72 79 70 74 69 6e 67 20 6c 6f 63 61 6c 20 64 72 69 76 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

