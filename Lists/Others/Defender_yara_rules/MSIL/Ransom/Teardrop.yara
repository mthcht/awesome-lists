rule Ransom_MSIL_Teardrop_AA_2147895897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Teardrop.AA!MTB"
        threat_id = "2147895897"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Teardrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "All Files Encrypted Love From Var0" ascii //weight: 20
        $x_1_2 = "disable_taskmgr" ascii //weight: 1
        $x_1_3 = "teardrop.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Var0Exploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

