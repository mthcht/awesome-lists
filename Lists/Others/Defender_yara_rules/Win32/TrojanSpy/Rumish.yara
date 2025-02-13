rule TrojanSpy_Win32_Rumish_A_2147649849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rumish.A"
        threat_id = "2147649849"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rumish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "er\\iexplore.exe\" ya.ru" ascii //weight: 1
        $x_1_2 = {72 75 6e 65 78 70 6c 5f 5c 52 65 6c 65 61 73 65 5c 73 6d 70 68 6f 73 74 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "%windir%\\system32\\smphost.exe" wide //weight: 1
        $x_1_4 = {2b c6 05 c8 00 00 00 3d e8 03 00 00 7d 0b 68 c8 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Rumish_B_2147649851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rumish.B"
        threat_id = "2147649851"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rumish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 42 72 6f 77 73 65 72 2e 48 65 6c 70 [0-3] 5c 42 72 6f 77 73 65 72 2e 48 65 6c 70 5c 52 65 6c 65 61 73 65 5c 72 76 72 73 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {26 62 72 77 73 76 3d 00 26 62 72 77 73 3d 00 00 26 69 65 3d 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Rumish_C_2147680072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rumish.C"
        threat_id = "2147680072"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rumish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "er\\iexplore.exe\" ya.ru" ascii //weight: 1
        $x_1_2 = "explWS\\runexpl\\Release\\psthost.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

