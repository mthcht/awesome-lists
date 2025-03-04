rule TrojanDownloader_Win32_GhostRat_CBI_2147851471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRat.CBI!MTB"
        threat_id = "2147851471"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0f 8b 56 10 fe c9 88 4d f0 3b 56 14 73 ?? 83 7e 14 10 8d 42 01 89 46 10 8b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_GhostRat_CCHU_2147904442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GhostRat.CCHU!MTB"
        threat_id = "2147904442"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 49 00 8a 8c 15 ?? ?? ?? ?? fe c9 88 8c 15 ?? ?? ?? ?? 42 3b d0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

