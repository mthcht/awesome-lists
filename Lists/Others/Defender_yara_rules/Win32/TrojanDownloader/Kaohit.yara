rule TrojanDownloader_Win32_Kaohit_A_2147691182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kaohit.A"
        threat_id = "2147691182"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaohit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDownload(arsiv_site, \"hash.txt\", 3, 1)" ascii //weight: 1
        $x_1_2 = "GetDownload(Site_Link, \"bg.txt\", 3, 1)" ascii //weight: 1
        $x_1_3 = "GetDownload(Atak_Link, \"hit.exe\", 3, 1)" ascii //weight: 1
        $x_1_4 = "taskkill /IM chrome.exe /F" ascii //weight: 1
        $x_1_5 = "wget.exe -O \"%A_AppData%\\arsiv.exe\" \"%hasharr1%\"" ascii //weight: 1
        $x_1_6 = "\"%Program_Path%\" +e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

