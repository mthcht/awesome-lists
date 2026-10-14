rule TrojanDownloader_Win64_ClipBanker_MK_2147980317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ClipBanker.MK!MTB"
        threat_id = "2147980317"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {89 55 e0 83 fa 05 ?? ?? 8d 0c 76 8a 04 3a 88 84 8a 4c c9 01 10 42}  //weight: 30, accuracy: Low
        $x_5_2 = "GOT-AC-2f9K7pQ1sVxZ" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

