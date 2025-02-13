rule Trojan_Win32_Nando_A_2147712129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nando.A!bit"
        threat_id = "2147712129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nando"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 00 42 00 4d 00 53 00 74 00 61 00 6d 00 70 00 00 00 00 00 46 00 42 00 4d 00 65 00 64 00 00 00 46 00 42 00 4d 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 46 00 42 00 4d 00 53 00 74 00 61 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "ping 127.0.0.1 -n 1 >nul & /c del /f /s /q %s & del /f /s /q %s & del /f /s /q" wide //weight: 1
        $x_1_3 = {00 6d 77 7c 76 3e 2a 2c 6c 69 73 6b 2d 64 75 29 60 73 26 65 6b 68 39 30 33 30 3c 2c 6b 69 76 60 2c 7d 76 60 64 77 6d 28 60 64 77 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 60 7b 78 6a 6b 77 66 7a 28 61 7d 66 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 6c 66 70 76 68 6a 71 6d 28 61 7d 66 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 67 62 61 62 71 67 71 67 71 77 60 71 26 63 7c 60 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 36 35 38 75 61 2b 66 70 63 00}  //weight: 1, accuracy: High
        $x_1_8 = "\\Deonan\\Release\\Deonan.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

