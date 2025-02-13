rule TrojanSpy_Win32_Stilcert_A_2147696909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stilcert.A"
        threat_id = "2147696909"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stilcert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "118.193.242.73" ascii //weight: 1
        $x_1_2 = "\\Program Files\\NPKI\\" ascii //weight: 1
        $x_1_3 = "\\Program Files\\logi.txt" ascii //weight: 1
        $x_1_4 = "csj.zip" ascii //weight: 1
        $x_1_5 = "FtpPutFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

