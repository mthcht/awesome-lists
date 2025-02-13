rule TrojanSpy_Win32_Fosin_A_2147665883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fosin.A"
        threat_id = "2147665883"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fosin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 1d 44 c6 44 24 1e 34 c6 44 24 1f 43 c6 44 24 20 32 c6 44 24 23 33 c6 44 24 26 30 c6 44 24 28 37 c6 44 24 2a 38 88 54 24 2b}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 04 40 3d ff 00 00 00 73 20 56 53 ff d7 83 c4 08 85 c0 75 15 56 8b}  //weight: 1, accuracy: High
        $x_1_3 = {2b c8 3b c2 8d 0c 88 8d 74 8d 00 b9 9d 00 00 00 f3 a5 7c 1b 55 e8}  //weight: 1, accuracy: High
        $x_1_4 = {34 2e 74 65 73 74 2e 33 33 32 32 2e 6f 72 67 2e 63 6e 00 00 33 2e 74 65 73 74}  //weight: 1, accuracy: High
        $x_1_5 = "pstenb.dat" wide //weight: 1
        $x_1_6 = "%04d%02d%02d%02d%02d%02d" wide //weight: 1
        $x_1_7 = "Global\\CODIRECT" wide //weight: 1
        $x_1_8 = "Global\\COPROX" wide //weight: 1
        $x_1_9 = "Global\\FSOIN" wide //weight: 1
        $x_1_10 = "Global\\pluol" wide //weight: 1
        $x_1_11 = "Global\\pluom" wide //weight: 1
        $x_1_12 = "newspy_killer" wide //weight: 1
        $x_1_13 = "deepscan\\speedmem2.hg" wide //weight: 1
        $x_1_14 = "deepscan\\cloudcom2.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

