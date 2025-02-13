rule TrojanDownloader_MSIL_StealC_ASE_2147898574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/StealC.ASE!MTB"
        threat_id = "2147898574"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 da 0b 16 0c 2b 15 02 08 02 08 9a 03 72 6b 02 00 70 6f 74 00 00 0a a2 08 17 d6 0c 08 07 31 e7}  //weight: 1, accuracy: High
        $x_1_2 = {25 16 07 a2 25 0c 14 14 17 8d 68 00 00 01 25 16 17 9c 25 0d 17 28 70 00 00 0a 26 09 16 91 2d 02 2b 1d 08 16 9a 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_StealC_RP_2147925381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/StealC.RP!MTB"
        threat_id = "2147925381"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 73 03 00 00 06 0a 06 6f 01 00 00 06 00 06 6f 1c 00 00 0a 26 2a}  //weight: 1, accuracy: High
        $x_10_2 = {7d 03 00 00 04 02 72 ?? ?? 00 70 7d ?? ?? 00 04 02 16 28 ?? ?? 00 0a 7d 05 00 00 04 02 72 ?? ?? 00 70 7d 06 00 00 04 02 28 ?? ?? 00 0a 00 00 02 28 ?? ?? 00 06 00 02 28 ?? ?? 00 06 16 fe 01 0a 06 2c 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

