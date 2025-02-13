rule TrojanDownloader_MSIL_Fsysna_SK_2147837076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fsysna.SK!MTB"
        threat_id = "2147837076"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 11 0a 11 05 94 58 11 09 11 05 94 58 20 00 01 00 00 5d 13 06 11 0a 11 05 94 13 08 11 0a 11 05 11 0a 11 06 94 9e 11 0a 11 06 11 08 9e 11 05 17 58 13 05 11 05 20 00 01 00 00 32 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Fsysna_SL_2147844063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fsysna.SL!MTB"
        threat_id = "2147844063"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 05 07 11 05 07 8e 69 5d 91 09 11 05 91 61 d2 9c 11 05 17 58 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Fsysna_SQ_2147893572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fsysna.SQ!MTB"
        threat_id = "2147893572"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 7b 12 00 00 04 6f ?? ?? ?? 06 00 17 28 ?? ?? ?? 0a 00 00 06 17 58 0a 06 20 f4 01 00 00 fe 04 0b 07 2d db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Fsysna_SR_2147925575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fsysna.SR!MTB"
        threat_id = "2147925575"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 08 6f 17 00 00 0a 0d 12 03 28 18 00 00 0a 28 19 00 00 0a 0b 08 17 58 0c 08 06 6f 1a 00 00 0a 32 dd}  //weight: 2, accuracy: High
        $x_2_2 = "Shiraza.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

