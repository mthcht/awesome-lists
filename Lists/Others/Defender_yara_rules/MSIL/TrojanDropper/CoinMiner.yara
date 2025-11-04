rule TrojanDropper_MSIL_CoinMiner_CC_2147956683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/CoinMiner.CC!MTB"
        threat_id = "2147956683"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 06 28 ?? 00 00 0a 02 6f ?? 00 00 0a 03 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 08 2b 2d 04 73 ?? 00 00 0a 13 04 17 13 09 2b bd d0 ?? ?? ?? ?? 1d 13 09 26 04 8e 69 8d ?? ?? ?? ?? 0b 18 13 09 2b a6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

