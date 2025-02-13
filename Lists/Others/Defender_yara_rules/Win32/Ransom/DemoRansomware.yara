rule Ransom_Win32_DemoRansomware_A_2147724596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DemoRansomware.A!!DemoRansomware.gen!A"
        threat_id = "2147724596"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DemoRansomware"
        severity = "Critical"
        info = "DemoRansomware: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 65 6e 63 72 79 70 74 65 64 21 00 2e 70 64 66 00 00 00 00 2e 77 61 76 00 00 00 00 2e 74 78 74 00 00 00 00 2e 6a 70 67 00 00 00 00 2e 62 6d 70}  //weight: 1, accuracy: High
        $x_1_2 = "</h2><img width=800 height=600 src=\"help_decrypt" ascii //weight: 1
        $x_1_3 = {7a 79 ee db f8 a0 df d1 23 9e f6 d5 51 36 cd dd 15 ba ee 72 39 b8 5d 8f b5 c5 63 d1 50 9a de f9 40 00 00 00 00 00 00 00 00 1e c8 f7 a5 86 fd d8}  //weight: 1, accuracy: High
        $x_1_4 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 69 33 c0 8a 44 24 08 84 c0 75 16 81 fa 80 00 00 00 72 0e 83 3d 70 52 41 00 00 74 05 e9 86 3f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

