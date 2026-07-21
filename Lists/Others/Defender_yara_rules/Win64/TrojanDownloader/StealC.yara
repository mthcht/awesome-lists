rule TrojanDownloader_Win64_StealC_AHB_2147974164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/StealC.AHB!MTB"
        threat_id = "2147974164"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {00 65 00 6e 00 74 00 65 00 72 00 70 00 72 00 69 00 73 00 65 00 2f 00 [0-15] 00 5f 00 73 00 2e 00 62 00 69 00 6e}  //weight: 30, accuracy: Low
        $x_20_2 = {ba 30 75 00 00 48 89 c1 c7 44 24 20 30 75 00 00 ff 15 ?? ?? ?? ?? 45 31 c9 41 b8 ?? 00 00 00 48 89 e9 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 49 89 c5 48 85 c0 75}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

