rule TrojanDownloader_MSIL_LummaStealer_RP_2147923327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaStealer.RP!MTB"
        threat_id = "2147923327"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 02 08 91 07 08 07 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LummaStealer_RP_2147923327_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LummaStealer.RP!MTB"
        threat_id = "2147923327"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0a 38 04 00 00 00 06 17 58 0a 06 1b 32 f8}  //weight: 10, accuracy: High
        $x_1_2 = {1b 0a 17 0b 17 0c 38 ?? ?? 00 00 07 08 5a 0b 08 17 58 0c 08 06 31 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

