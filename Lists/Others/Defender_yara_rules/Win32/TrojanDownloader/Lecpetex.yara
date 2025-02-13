rule TrojanDownloader_Win32_Lecpetex_B_2147688323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lecpetex.B"
        threat_id = "2147688323"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecpetex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 ec 81 7d ec 90 22 9f 53 72 08 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "/images/stories/footballfield.jpg" ascii //weight: 1
        $x_1_3 = "176.9.11.216" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

