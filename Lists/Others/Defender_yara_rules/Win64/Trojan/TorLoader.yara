rule Trojan_Win64_TorLoader_CZ_2147926867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TorLoader.CZ!MTB"
        threat_id = "2147926867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TorLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OTTOttcfwOFFwOF2PK" ascii //weight: 2
        $x_2_2 = "Zr2JFtRQNX3BCZ8YtxRE9hNJYC8J6I1MVbMg6owUp18" ascii //weight: 2
        $x_2_3 = "GyT4nK/YDHSqa1c4753ouYCDajOYKTja9Xb/OHtgvSw" ascii //weight: 2
        $x_1_4 = "NjRFUR3zs1JPUCgaCXSh3SW62uAKT1mSBM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

