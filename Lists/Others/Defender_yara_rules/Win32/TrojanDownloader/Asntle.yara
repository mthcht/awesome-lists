rule TrojanDownloader_Win32_Asntle_A_2147720961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Asntle.A"
        threat_id = "2147720961"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Asntle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v EnableBalloonTips /t REG_DWORD /d 0 /f" wide //weight: 1
        $x_1_2 = ":\\Users\\jpvic\\Desktop\\VB6DLL\\PROFULL_NODLL_SPLIT_AND_RES\\Project1.vbp" wide //weight: 1
        $x_1_3 = "(LoadAntis)" wide //weight: 1
        $x_1_4 = "(LoadKiller)" wide //weight: 1
        $x_1_5 = "/v DisableAntiSpyware /t REG_DWORD /d 0 /f" wide //weight: 1
        $x_1_6 = "\\PH.vm -s -c -ctype process -cobject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

