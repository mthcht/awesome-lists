rule PWS_Win32_Nessun_A_2147689155_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nessun.A"
        threat_id = "2147689155"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nessun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 6b 65 79 72 65 67 3d 4d 79 53 65 72 76 65 72}  //weight: 2, accuracy: High
        $x_2_2 = {00 36 45 34 31 35 44 35 34 34 36 34 35 35 33 34 30 35 37 36 45 35 46 35 42 35 31 34 30 35 44 34 31 35 44 35 34 34 36 36 45 34 35 35 42 35 43 35 36 35 44 34 35 34 31 36 45 35 31 34 37 34 30 34 30 35 37 35 43 34 36 34 34 35 37 34 30 34 31 35 42 35 44 35 43 36 45 34 30 34 37 35 43 36 45 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 2f 43 20 52 45 47 20 41 44 44 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76}  //weight: 2, accuracy: High
        $x_2_4 = {00 4e 65 73 73 75 6e 20 61 72 63 68 69 76 69 6f 20 6b 65 79 6c 6f 67 67 65 72 20 69 6e 20 71 75 65 73 74 65 20 64 61 74 65 00}  //weight: 2, accuracy: High
        $x_1_5 = {8b d0 8b 45 f8 0f b6 44 18 ff 33 d0 8d 45 f4 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? 83 c6 02 43 8b 45 f8 e8 ?? ?? ?? ?? 3b d8 7e 05 bb 01 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 3b f0 7e 96}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

