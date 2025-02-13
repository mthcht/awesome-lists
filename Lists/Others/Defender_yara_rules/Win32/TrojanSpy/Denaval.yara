rule TrojanSpy_Win32_Denaval_A_2147605822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Denaval.gen!A"
        threat_id = "2147605822"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Denaval"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\System\\Drivers.exe" wide //weight: 1
        $x_1_2 = {74 00 69 00 74 00 6f 00 73 00 2e 00 45 00 58 00 45 00 00 00 1a 00 00 00 44 00 65 00 73 00 63 00}  //weight: 1, accuracy: High
        $x_1_3 = "/v DisableRegistryTools /t REG_DWORD /d" wide //weight: 1
        $x_1_4 = "/v DisableTaskMgr /t REG_DWORD /d" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = {72 00 69 00 76 00 65 00 72 00 73 00 00 00 16 00 00 00 6d 00 73 00 6e 00 6d 00 73 00 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

