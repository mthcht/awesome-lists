rule TrojanDownloader_MSIL_Rhadamanthys_A_2147841130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Rhadamanthys.A!MTB"
        threat_id = "2147841130"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Rhadamanthys_B_2147842342_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Rhadamanthys.B!MTB"
        threat_id = "2147842342"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 03 8e 69 17 59 0b 38}  //weight: 2, accuracy: High
        $x_2_2 = {03 06 91 0c 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32}  //weight: 2, accuracy: High
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Rhadamanthys_ARD_2147844015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Rhadamanthys.ARD!MTB"
        threat_id = "2147844015"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 28 05 00 00 06 0a 28 02 00 00 0a 06 6f 03 00 00 0a 28 04 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de d6}  //weight: 1, accuracy: High
        $x_1_2 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

