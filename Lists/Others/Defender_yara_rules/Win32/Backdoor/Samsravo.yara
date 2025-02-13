rule Backdoor_Win32_Samsravo_A_2147691983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Samsravo.A"
        threat_id = "2147691983"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Samsravo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c db 8d 34 8e b9 09 00 00 00 8d 7d 84 f3 a5 6a 24 8b 55 84 52 8b 45 08 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 40 84 d2 75 f9 8b 56 10 2b c1 6a 14 83 c0 09 52 89 44 24 1c ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 10 51 8b 4c 24 10 68 0a 20 26 00 52 50 51 c7 06}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 52 00 4d 00 73 00 76 00 72 00 00 00 00 00 2d 00 75 00}  //weight: 1, accuracy: High
        $x_1_5 = "{MSC.W1758F-AA438F129C.CFF}" wide //weight: 1
        $x_1_6 = {5c 53 55 44 50 5c 52 65 6c 65 61 73 65 5c [0-16] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_7 = "NeddyService.pdb" ascii //weight: 1
        $x_1_8 = {75 f9 2b d1 33 c9 85 d2 7e 13 8a 81 ?? ?? 41 00 34 fd 88 81 ?? ?? 41 00 41 3b ca 7c ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

