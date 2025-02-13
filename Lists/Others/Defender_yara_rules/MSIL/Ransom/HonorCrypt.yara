rule Ransom_MSIL_HonorCrypt_PA_2147769481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HonorCrypt.PA!MTB"
        threat_id = "2147769481"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HonorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".honor" wide //weight: 1
        $x_1_2 = "Honor's Malware" wide //weight: 1
        $x_1_3 = "secretAES.txt" wide //weight: 1
        $x_1_4 = "\\honor's malware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

