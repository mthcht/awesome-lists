rule TrojanDownloader_Win32_TinyBanker_GZN_2147814245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/TinyBanker.GZN!MTB"
        threat_id = "2147814245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 9c 24 db 01 00 00 88 cf 28 df 66 89 c6 66 21 f2 66 89 94 24 ?? ?? ?? ?? 88 bc 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 8b 4c 24 2c 01 c8 89 84 24 ?? ?? ?? ?? e9 3d ff ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = "DebugBreak" ascii //weight: 1
        $x_1_3 = "srand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

