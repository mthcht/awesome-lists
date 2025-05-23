rule Trojan_MSIL_DaVinci_MBZ_2147942071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DaVinci.MBZ!MTB"
        threat_id = "2147942071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DaVinci"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 00 65 00 74 00 2e 00 61 00 6c 00 70 00 68 00 61 00 00 13 67 00 68 00 6f 00 73 00 74 00 2e 00 64 00 6c 00 6c 00 00 17 70 00 68 00 61 00 6e 00 74 00 6f 00 6d 00 2e 00 65 00 78}  //weight: 2, accuracy: High
        $x_1_2 = "DoAnCaNhan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

