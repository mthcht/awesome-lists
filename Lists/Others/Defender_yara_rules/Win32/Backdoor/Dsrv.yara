rule Backdoor_Win32_Dsrv_A_2147679758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dsrv.A"
        threat_id = "2147679758"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dsrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~Thumbbs.TMP" ascii //weight: 1
        $x_1_2 = "RunDll32xVd.exe" ascii //weight: 1
        $x_1_3 = "UrlDownFileAndRun" ascii //weight: 1
        $x_1_4 = "UpServeFile" ascii //weight: 1
        $x_1_5 = "c:\\DLLService.TXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

