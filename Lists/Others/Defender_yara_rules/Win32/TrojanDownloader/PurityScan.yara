rule TrojanDownloader_Win32_PurityScan_MI_2147744198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PurityScan.MI!MTB"
        threat_id = "2147744198"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PurityScan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 fb 8b fe 2b f9 c1 e2 ?? 8d 9a ?? ?? ?? 00 8d 04 0f 6a ?? 99 5d f7 fd 8a 82 ?? ?? ?? 00 8b 54 24 ?? 32 01 ff 44 24 ?? 41 39 74 24 ?? 88 04 13}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\ClickSpring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

