rule TrojanSpy_Win32_Nussamoc_A_2147627003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nussamoc.A"
        threat_id = "2147627003"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nussamoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d7 07 76 05 e8 ?? ?? ff ff 66 81 ?? ?? ?? ?? 00 d7 07 76 17}  //weight: 2, accuracy: Low
        $x_2_2 = {76 26 be 01 00 00 00 8d 45 f4 8b 55 fc 8a 54 32 ff 80 f2 01}  //weight: 2, accuracy: High
        $x_1_3 = {74 16 68 a0 68 06 00 e8 ?? ?? ?? ?? 8b d7 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_4 = {69 64 2e 70 68 70 3f 72 61 6e 64 6f 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 64 61 74 65 2e 70 68 70 3f 6f 73 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "name=\"filename1\"; filename=\"pass.txt\"" ascii //weight: 1
        $x_1_7 = "name=\"filename2\"; filename=\"screen.jpg\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

