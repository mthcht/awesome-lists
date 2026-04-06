rule TrojanDownloader_Win64_PowDow_SX_2147966384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/PowDow.SX!MTB"
        threat_id = "2147966384"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Root2Bypass" ascii //weight: 20
        $x_10_2 = "powershell iex ( irm raw." ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

