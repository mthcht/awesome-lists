rule Trojan_MSIL_SheetCreep_GVA_2147962503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SheetCreep.GVA!MTB"
        threat_id = "2147962503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SheetCreep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 8d 00 00 70 03 72 97 00 00 70 28 0d 00 00 0a 6f 0e 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\Public\\Documents\\" wide //weight: 1
        $x_2_3 = "GServices.png" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

