rule TrojanSpy_Win32_Sycomder_A_2147660035_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sycomder.A"
        threat_id = "2147660035"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sycomder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 d0 50 e8 ?? ?? ?? ?? 6a 00 ff 75 08 6a 00 6a 00 68 ?? ?? 00 00 68 ?? ?? 00 00 6a 6b 68 ?? ?? 00 00 68 00 00 0a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 89 45 b0 6a 01}  //weight: 1, accuracy: Low
        $x_1_2 = "Detective" ascii //weight: 1
        $x_1_3 = "DIT4> %TEMP%" ascii //weight: 1
        $x_1_4 = {3e 3e 20 25 54 45 4d 50 25 5c [0-8] 2e 5f 65 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Sycomder_B_2147672229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sycomder.B"
        threat_id = "2147672229"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sycomder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sys.dat" ascii //weight: 1
        $x_2_2 = "{BUFFER BEGIN}" ascii //weight: 2
        $x_2_3 = "{Continue!}" ascii //weight: 2
        $x_2_4 = "{Right}" ascii //weight: 2
        $x_3_5 = "\\autoinstall.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

