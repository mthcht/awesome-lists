rule TrojanDownloader_MSIL_Tedy_NE_2147830481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tedy.NE!MTB"
        threat_id = "2147830481"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 14 00 00 0a 25 72 01 00 00 70 6f 15 00 00 0a 25 17 6f 16 00 00 0a 25 72 17 00 00 70 6f 17 00 00 0a 28 18 00 00 0a 26 2a}  //weight: 2, accuracy: High
        $x_2_2 = "ETH COINt.WTF COINlIOSNT" wide //weight: 2
        $x_2_3 = "$TRUMP" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

