rule TrojanDownloader_Win32_RaccoonStealerv2_A_2147899019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/RaccoonStealerv2.A!MTB"
        threat_id = "2147899019"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonStealerv2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 14 30 83 c0 ?? 3b c1}  //weight: 2, accuracy: Low
        $x_2_2 = {31 34 11 83 c1 ?? 3b c8}  //weight: 2, accuracy: Low
        $x_2_3 = {30 04 32 8d 41 ?? 33 c9 42}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

