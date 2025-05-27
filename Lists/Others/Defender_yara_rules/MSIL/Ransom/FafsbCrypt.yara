rule Ransom_MSIL_FafsbCrypt_PA_2147942250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FafsbCrypt.PA!MTB"
        threat_id = "2147942250"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FafsbCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".crpt" wide //weight: 1
        $x_1_2 = "IsTestTrue.txt" wide //weight: 1
        $x_1_3 = "DumpStack.log.tmp" wide //weight: 1
        $x_2_4 = "\\Hacker.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

