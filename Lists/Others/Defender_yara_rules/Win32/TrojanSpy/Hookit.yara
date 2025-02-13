rule TrojanSpy_Win32_Hookit_A_2147636686_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hookit.A"
        threat_id = "2147636686"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hookit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c2 47 86 c8 61 8b f2 83 e6 03 8b 34 b7 8b f8 c1 ef 05 8b d8 c1 e3 04 0f ce}  //weight: 1, accuracy: High
        $x_1_2 = {3d 53 cf 99 ec 74 f4 3d c9 8a 64 6b 74 ed 33 c9 3d 8e 38 f8 79 0f 94 c1 8b c1 c9 c3}  //weight: 1, accuracy: High
        $x_1_3 = {8d 74 06 05 80 3e e9 74 f4 8b 06 3d 8b ff 55 8b 74 07 3d cc ff 55 8b 75 32}  //weight: 1, accuracy: High
        $x_1_4 = {2b fe 6a 05 83 ef 05 56 c6 06 e9 89 7e 01 ff d3 b0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

