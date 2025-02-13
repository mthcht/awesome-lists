rule Ransom_MSIL_KfualdCrypt_PA_2147780355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KfualdCrypt.PA!MTB"
        threat_id = "2147780355"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KfualdCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".kfuald" wide //weight: 1
        $x_1_2 = "_Encrypted$" wide //weight: 1
        $x_1_3 = "UmFuc29tJA==" wide //weight: 1
        $x_1_4 = {5c 52 61 6e 73 6f 6d 5c 52 61 6e 73 6f 6d 5c [0-8] 5c [0-16] 5c 52 61 6e 73 6f 6d 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

