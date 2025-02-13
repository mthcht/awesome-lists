rule TrojanDownloader_Win32_RemcosRAT_A_2147892025_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/RemcosRAT.A!MTB"
        threat_id = "2147892025"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c8 0f b7 c3 8b ea 99 03 c8 13 d5 33 c0 33 c8 33 d7 8b f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

