rule Ransom_MSIL_Choas_GVA_2147945878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Choas.GVA!MTB"
        threat_id = "2147945878"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Choas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d fe 0e 23 00 fe 0c 1f 00 fe 0c 1f 00 1f 12 62 61 fe 0e 1f 00 fe 0c 1f 00 fe 0c 20 00 58 fe 0e 1f 00 fe 0c 1f 00 fe 0c 1f 00 17 64 61 fe 0e 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

