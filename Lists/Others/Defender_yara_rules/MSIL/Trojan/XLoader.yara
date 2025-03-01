rule Trojan_MSIL_XLoader_RDA_2147846100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XLoader.RDA!MTB"
        threat_id = "2147846100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dkdFIh" ascii //weight: 1
        $x_2_2 = {02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XLoader_SVPF_2147925096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XLoader.SVPF!MTB"
        threat_id = "2147925096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0b 11 0b 1f 7b 61 20 ff 00 00 00 5f 13 0c 11 0c 20 c8 01 00 00 58 20 00 01 00 00 5e 13 0c 11 0c 16 fe 01 13 0d}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

