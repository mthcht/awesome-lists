rule TrojanDownloader_Win32_VBokinfi_A_2147717851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VBokinfi.A"
        threat_id = "2147717851"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VBokinfi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ftp://ftp.okinfinityok" wide //weight: 1
        $x_1_2 = "fuck10" wide //weight: 1
        $x_1_3 = "ban.zip" wide //weight: 1
        $x_1_4 = {63 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 5c 00 43 00 65 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

