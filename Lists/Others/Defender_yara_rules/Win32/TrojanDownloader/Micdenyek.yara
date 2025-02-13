rule TrojanDownloader_Win32_Micdenyek_A_2147651876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Micdenyek.A"
        threat_id = "2147651876"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Micdenyek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "DCIM_0%5!d!.jpg" ascii //weight: 5
        $x_5_2 = {25 31 21 73 21 5c 25 32 21 73 ?? 2e 64 6c 6c}  //weight: 5, accuracy: Low
        $x_5_3 = "bytes=%1!d!" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

