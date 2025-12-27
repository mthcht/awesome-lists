rule Ransom_MSIL_Crypticware_PA_2147945539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypticware.PA!MTB"
        threat_id = "2147945539"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypticware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crypticware" wide //weight: 1
        $x_1_2 = "SimpleXOREncryption" ascii //weight: 1
        $x_3_3 = "Your important files has been encrypted with Crypticware." wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

