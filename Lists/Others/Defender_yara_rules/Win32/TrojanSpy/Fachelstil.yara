rule TrojanSpy_Win32_Fachelstil_STB_2147781732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fachelstil.STB"
        threat_id = "2147781732"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fachelstil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 65 00 76 00 65 00 6e 00 74 00 73 00 3f 00 64 00 65 00 76 00 69 00 63 00 65 00 3d 00 [0-4] 26 00 70 00 77 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 73 00 63 00 72 00 65 00 65 00 6e 00 3f 00 64 00 65 00 76 00 69 00 63 00 65 00 3d 00 [0-4] 26 00 70 00 77 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 74 00 61 00 73 00 6b 00 73 00 3f 00 64 00 65 00 76 00 69 00 63 00 65 00 3d 00 [0-4] 26 00 70 00 77 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 66 00 73 00 3f 00 64 00 65 00 76 00 69 00 63 00 65 00 3d 00 [0-4] 26 00 70 00 77 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 00 66 00 73 00 2f 00 74 00 72 00 65 00 65 00 3f 00 64 00 65 00 76 00 69 00 63 00 65 00 3d 00 [0-4] 26 00 70 00 77 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 2d 00 66 00 20 00 22 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-64] 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

