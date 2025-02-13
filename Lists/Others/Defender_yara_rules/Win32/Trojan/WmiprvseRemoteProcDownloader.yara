rule Trojan_Win32_WmiprvseRemoteProcDownloader_A_2147846903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmiprvseRemoteProcDownloader.A!ibt"
        threat_id = "2147846903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmiprvseRemoteProcDownloader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c" wide //weight: 1
        $x_1_2 = " powershell" wide //weight: 1
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 69 00 [0-53] 2f 00 70 00 6f 00 77 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

