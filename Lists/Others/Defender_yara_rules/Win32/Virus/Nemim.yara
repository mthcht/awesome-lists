rule Virus_Win32_Nemim_A_2147679306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Nemim.gen!A"
        threat_id = "2147679306"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d f8 00 00 00 73 0a be fd ff ff ff e9 e5 03 00 00 3d 00 00 80 0c 76 0a be f6 ff ff ff e9 d4 03 00 00 8b 4d 00 3b cf 75 04}  //weight: 1, accuracy: High
        $x_1_2 = {f3 a5 b9 4d 5a 00 00 66 39 08 74 0a be}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 80 00 00 6a 00 8b 85 6c fd ff ff 50 ff 95 c8 fa ff ff 8b 4d f4 51 ff 95 c4 fe ff ff ff 95 e0 fb ff ff 33 c0 8b e5}  //weight: 1, accuracy: High
        $x_1_4 = {66 69 7c 66 73 65 66 62 5c 65 6a 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {89 4d dc 8a 4d dc 88 4d eb eb ae 8b 55 08 03 55 e4 8a 45 eb 88 02 eb 83 8b 4d fc 83 e9 01 89 4d fc eb 09 8b 55 fc 83 ea 01}  //weight: 1, accuracy: High
        $x_1_6 = {88 0a eb cd 8b 55 ec 83 c2 04 89 55 ec 8b 85 c4 fa ff ff 89 85 98 fa ff ff c7 85 9c fa ff ff 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {83 f9 36 75 20 8b 95 b8 fe ff ff 0f be 42 01 83 f8 2a 75 11 8b 8d b8 fe ff ff 0f be 51 02 83 fa 23 75 02}  //weight: 1, accuracy: High
        $x_1_8 = {83 fa 3a 0f 84 ac 00 00 00 8b 85 d0 fe ff ff 8b 8d b8 fe ff ff 8a 11 88 94 05 e0 fe ff ff 8b 85 b8 fe ff ff 0f be 08 83 f9 2e 0f 85 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

