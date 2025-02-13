rule TrojanDownloader_Win32_Cerewow_A_2147692008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cerewow.A"
        threat_id = "2147692008"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerewow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/landing?action=report" ascii //weight: 1
        $x_1_2 = "/landing?action=ping" ascii //weight: 1
        $x_1_3 = "/landing?action=file" ascii //weight: 1
        $x_1_4 = "/landing?action=jsfile&systemhash=%s&" ascii //weight: 1
        $x_10_5 = "systeminjected" ascii //weight: 10
        $x_10_6 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENT VERSION\\RUN" ascii //weight: 10
        $x_10_7 = "isnet20inst" ascii //weight: 10
        $x_10_8 = "%WINDIR%/temp/1.txt" ascii //weight: 10
        $x_10_9 = "31.184.194.99" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

