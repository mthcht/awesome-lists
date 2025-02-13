rule Ransom_MSIL_JigsawCrypt_PA_2147809583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawCrypt.PA!MTB"
        threat_id = "2147809583"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Saher Blue Eagle" wide //weight: 1
        $x_1_2 = "jigsaw-ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

