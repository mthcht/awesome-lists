rule TrojanDownloader_Win64_Penguish_PO_2147913345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Penguish.PO!MTB"
        threat_id = "2147913345"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Penguish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 83 7c 24 ?? ?? 7f ?? 8b 44 24 ?? 8b 4c 24 ?? 33 c8 8b c1 85 c0 7d ?? 8b 44 24 ?? d1 e0 33 44 24 ?? 89 44 24 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

