rule TrojanDownloader_Win64_BazaarLoader_AA_2147767093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/BazaarLoader.AA!MTB"
        threat_id = "2147767093"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c1 6b c8 3e b8 09 04 02 81 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 42 ?? ?? ?? ?? 49 ff c0 49 83 f8 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

