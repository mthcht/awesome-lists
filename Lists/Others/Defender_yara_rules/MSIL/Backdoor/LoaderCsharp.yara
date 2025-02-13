rule Backdoor_MSIL_LoaderCsharp_A_2147788071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/LoaderCsharp.A"
        threat_id = "2147788071"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LoaderCsharp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.registerservicesinfo.com/favicon.ico" wide //weight: 10
        $x_10_2 = "\\LoaderCsharp\\obj\\Release\\LoaderCsharp.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

