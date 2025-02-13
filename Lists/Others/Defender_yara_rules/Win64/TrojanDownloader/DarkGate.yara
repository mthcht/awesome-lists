rule TrojanDownloader_Win64_DarkGate_A_2147891918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DarkGate.A!MTB"
        threat_id = "2147891918"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 13 44 0f b6 04 03 44 88 04 13 48 83 c2 ?? 88 0c 03 48 83 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {44 0f b6 0c 01 48 83 c2 ?? 44 88 4a ?? 44 88 04 01 48 83 e8 ?? 45 89 d0 41 29 c0 41 39 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

