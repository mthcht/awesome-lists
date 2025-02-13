rule TrojanSpy_Win32_Gravad_A_2147665950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gravad.A"
        threat_id = "2147665950"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gravad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Captura AVI_original\\MeConte_gravador" wide //weight: 1
        $x_1_2 = {65 00 73 00 70 00 65 00 72 00 61 00 6e 00 64 00 6f 00 20 00 63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 61 00 e7 00 e3 00 6f 00 20 00 64 00 65 00 20 00 70 00 61 00 67 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 62 00 63 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6b 65 79 6c 6f 67 67 65 72 00 00 00 4d 6f 64 75 6c 65 31 00 63 44 69 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

