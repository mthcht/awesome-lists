rule TrojanDownloader_Win32_SBadur_MK_2147980842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SBadur.MK!MTB"
        threat_id = "2147980842"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/raw/bk7NmDe3" ascii //weight: 10
        $x_5_2 = "Manual Inject Cheat" ascii //weight: 5
        $x_3_3 = "[5] Check HWID" ascii //weight: 3
        $x_2_4 = "LOADER SELECTED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

