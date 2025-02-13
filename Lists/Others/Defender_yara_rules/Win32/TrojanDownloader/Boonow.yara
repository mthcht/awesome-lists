rule TrojanDownloader_Win32_Boonow_A_2147718626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Boonow.A"
        threat_id = "2147718626"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Boonow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 [0-16] 53 6f 66 74 77 61 72 65 5c 6e 65 77 62 61 79}  //weight: 1, accuracy: Low
        $x_1_2 = "Payload downloaded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

