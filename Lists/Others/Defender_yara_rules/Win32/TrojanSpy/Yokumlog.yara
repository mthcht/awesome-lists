rule TrojanSpy_Win32_Yokumlog_A_2147710753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Yokumlog.A"
        threat_id = "2147710753"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Yokumlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\WindowsComodo\\svchost.exe +h +a" ascii //weight: 1
        $x_1_2 = "yokmu logger" ascii //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-32] 2e 00 63 00 6f 00 6d 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

