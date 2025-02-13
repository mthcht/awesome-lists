rule TrojanDownloader_Win64_DuckTail_A_2147923739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DuckTail.A!MTB"
        threat_id = "2147923739"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 0f be c0 48 8b 44 ?? ?? 48 8b 0c ?? 0f be 14 08 44 31 c2 88 14 08 48 8b 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

