rule TrojanSpy_Win32_Keodoct_A_2147709650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keodoct.A!bit"
        threat_id = "2147709650"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keodoct"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 00 72 00 20 00 4f 00 6f 00 64 00 6f 00 63 00 20 00 72 00 65 00 70 00 6f 00 72 00 74 00 69 00 6e 00 67 00 20 00 2c 00 20 00 54 00 68 00 69 00 73 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 [0-32] 49 00 73 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Server\\OodocKeyBoard.okb" wide //weight: 1
        $x_1_3 = "Server\\Oodoc.exe" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\Currentversion\\Run" wide //weight: 1
        $x_1_5 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

