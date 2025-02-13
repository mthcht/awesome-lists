rule Ransom_MSIL_SparkCrypt_PA_2147818492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SparkCrypt.PA!MTB"
        threat_id = "2147818492"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SparkCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Spark" wide //weight: 1
        $x_1_2 = "RANSOMWARE3._0" wide //weight: 1
        $x_1_3 = "shutdown /r /t 0" wide //weight: 1
        $x_1_4 = "\\RANSOMWARE3.0.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

