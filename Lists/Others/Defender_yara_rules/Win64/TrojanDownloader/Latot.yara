rule TrojanDownloader_Win64_Latot_ARAC_2147891508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Latot.ARAC!MTB"
        threat_id = "2147891508"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Latot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 ff c1 41 f7 e8 8b c2 c1 e8 1f 03 d0 0f b6 c2 02 c0 02 d0 41 0f b6 c0 41 ff c0 2a c2 04 02 00 44 31 ff 49 3b c9 7c d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

