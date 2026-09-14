rule Trojan_MSIL_DiskWriter_EAOZ_2147942197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiskWriter.EAOZ!MTB"
        threat_id = "2147942197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 15 06 07 02 07 ?? ?? ?? ?? ?? 20 00 01 00 00 5d d2 9c 07 17 58 0b 07 20 f8 2f 14 00 32 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiskWriter_A_2147978151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiskWriter.A!MTB"
        threat_id = "2147978151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {08 04 16 20 00 04 00 00 6f 14 00 00 0a 08 17 6f 15 00 00 0a 08 05 16 20 00 03 00 00 6f 14 00 00 0a}  //weight: 20, accuracy: High
        $x_5_2 = "MbrWriter" ascii //weight: 5
        $x_5_3 = "WriteToDisk" ascii //weight: 5
        $x_5_4 = "PayloadReader" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

