rule Backdoor_Win32_Funkybase_A_2147710103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Funkybase.A!dha"
        threat_id = "2147710103"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Funkybase"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 3c 43 c6 44 24 3d 6f c6 44 24 3e 6e c6 44 24 3f 6e 88 44 24 40 88 54 24 41 88 4c 24 42 c6 44 24 43 69 c6 44 24 44 6f c6 44 24 45 6e c6 44 24 46 3a c6 44 24 47 20 c6 44 24 48 6b 88 44 24 49 88 44 24 4a c6 44 24 4b 70 c6 44 24 4c 2d c6 44 24 4d 61 c6 44 24 4e 6c c6 44 24 4f 69 c6 44 24 50 76}  //weight: 1, accuracy: High
        $x_1_2 = {c6 84 24 c8 00 00 00 69 c6 84 24 c9 00 00 00 6f c6 84 24 ca 00 00 00 6e c6 84 24 cb 00 00 00 2f c6 84 24 cc 00 00 00 78 c6 84 24 cd 00 00 00 6d c6 84 24 ce 00 00 00 6c c6 84 24 cf 00 00 00 3b c6 84 24 d0 00 00 00 71 c6 84 24 d1 00 00 00 3d c6 84 24 d2 00 00 00 30 c6 84 24 d3 00 00 00 2e c6 84 24 d4 00 00 00 39 c6 84 24 d5 00 00 00 2c c6 84 24 d6 00 00 00 2a c6 84 24 d7 00 00 00 2f c6 84 24 d8 00 00 00 2a c6 84 24 d9 00 00 00 3b c6 84 24 da 00 00 00 71 c6 84 24 db 00 00 00 3d c6 84 24 dc 00 00 00 30 c6 84 24 dd 00 00 00 2e c6 84 24 de 00 00 00 38}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 3c 50 c6 44 24 3d 72 c6 44 24 3e 61 c6 44 24 3f 67 c6 44 24 40 6d c6 44 24 41 61 c6 44 24 42 3a c6 44 24 43 20 c6 44 24 44 6e c6 44 24 45 6f c6 44 24 46 2d 88 54 24 47 c6 44 24 48 61 88 54 24 49 c6 44 24 4a 68 c6 44 24 4c 0d c6 44 24 4d 0a 88 5c 24 4e c6 44 24 6c 43 c6 44 24 6d 61}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 76 72 c6 44 24 77 6f c6 44 24 78 6c c6 44 24 79 3a c6 44 24 7a 20 c6 44 24 7b 6e c6 44 24 7c 6f c6 44 24 7d 2d 88 54 24 7e c6 44 24 7f 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

