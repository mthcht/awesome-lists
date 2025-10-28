rule Ransom_MSIL_Hexamethy_SK_2147956206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hexamethy.SK!MTB"
        threat_id = "2147956206"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hexamethy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are in hostage by the HEXAMETHYLCYCLOTRISILOXANE Ransomware!" ascii //weight: 1
        $x_1_2 = "RAPIDOVERWRITER.exe" ascii //weight: 1
        $x_1_3 = ".HXAMTHY" ascii //weight: 1
        $x_1_4 = "Hexamethy_decryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

