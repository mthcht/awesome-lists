rule TrojanDownloader_Win32_AgentTesla_CCHW_2147905171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AgentTesla.CCHW!MTB"
        threat_id = "2147905171"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 1a 8a 1c 31 32 d3 8b 5d ?? 88 14 01 b8 01 00 00 00 03 c7 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

