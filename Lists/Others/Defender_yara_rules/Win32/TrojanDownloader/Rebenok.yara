rule TrojanDownloader_Win32_Rebenok_A_2147621191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rebenok.A"
        threat_id = "2147621191"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebenok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s%itmp.exe" ascii //weight: 10
        $x_10_2 = "bot_main()" ascii //weight: 10
        $x_10_3 = "http://bot:" ascii //weight: 10
        $x_10_4 = "http_download()" ascii //weight: 10
        $x_10_5 = "antidebug_detectdebugger()" ascii //weight: 10
        $x_10_6 = "%s%s%s%s unable to kill %sthread:%s %i!" ascii //weight: 10
        $x_1_7 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

