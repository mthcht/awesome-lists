rule TrojanSpy_Win32_Stildat_A_2147722728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stildat.A"
        threat_id = "2147722728"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stildat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|#|DownloadFile|#|Command" ascii //weight: 1
        $x_1_2 = "M:SF?commandId=CmdResult=" ascii //weight: 1
        $x_1_3 = "ExecuteKL" ascii //weight: 1
        $x_1_4 = "GetConfig:::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

