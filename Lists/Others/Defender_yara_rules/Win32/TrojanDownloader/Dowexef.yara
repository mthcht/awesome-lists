rule TrojanDownloader_Win32_Dowexef_B_2147705946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dowexef.B"
        threat_id = "2147705946"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowexef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c2 83 ea 20 80 fa 5a 8d 69 01 0f 86 ?? ?? 00 00 83 f8 39 0f 8f ?? ?? 00 00 83 fe 03 0f 87 ?? ?? 00 00 83 f8 2f 0f 8e ?? ?? 00 00 85 f6 0f 84 ?? ?? 00 00 83 fe 02}  //weight: 1, accuracy: Low
        $x_1_2 = ".DownloadFile('%s','%s'); Start-Process '%s" ascii //weight: 1
        $x_1_3 = "pdf.dll, error code 126" ascii //weight: 1
        $x_1_4 = "@powershell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

