rule TrojanDownloader_Win32_OzoneRAT_A_2147851945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/OzoneRAT.A!MTB"
        threat_id = "2147851945"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "OzoneRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 43 04 6a 00 6a 01 6a 02 e8 ?? ff ff ff 89 43 10 66 c7 45 ec 02 00 56 e8 ?? fe ff ff 66 89 45 ee 8b 43 04 50 e8 ?? fe ff ff 89 45 f0 33 c0 5a 59 59 64 89 10 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {66 2b 1e 8b cb 0f b7 07 66 d3 e0 66 09 45}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

