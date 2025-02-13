rule TrojanDownloader_Win32_WhisperGate_AWH_2147899882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WhisperGate.AWH!MTB"
        threat_id = "2147899882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 a0 b0 40 00 c7 45 f0 c4 b0 40 00 8b 45 10 89 44 24 10 8b 45 0c 89 44 24 0c 8b 45 08 89 44 24 08 8b 45 f0 89 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

