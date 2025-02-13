rule TrojanSpy_Win32_Batund_A_2147666204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Batund.A"
        threat_id = "2147666204"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Batund"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/ok.php?a=%username%&b=%computername%&c=%mac%\")&&fsutil file createnew \"%temp%\\thunb.db" ascii //weight: 5
        $x_1_2 = "\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 0" ascii //weight: 1
        $x_1_3 = "\\Domains\\com.br\\*.bradesco\" /v \"http\" /t REG_DWORD /d \"0x00000002\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

