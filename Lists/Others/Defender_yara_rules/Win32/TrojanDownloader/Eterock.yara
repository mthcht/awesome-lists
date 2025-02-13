rule TrojanDownloader_Win32_Eterock_A_2147721503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Eterock.A"
        threat_id = "2147721503"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Eterock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchost.exe" wide //weight: 1
        $x_1_2 = "\\TaskScheduler" wide //weight: 1
        $x_1_3 = "Finished MkDir Temp" wide //weight: 1
        $x_1_4 = "\\required.glo" wide //weight: 1
        $x_1_5 = "\\dotnetfx.exe /q:a /c:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

