rule Ransom_MSIL_LockyCrypt_PA_2147782021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockyCrypt.PA!MTB"
        threat_id = "2147782021"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locky" wide //weight: 1
        $x_1_2 = "[LockTXTFiles]" wide //weight: 1
        $x_1_3 = "Not yet pay BTCAmount=" wide //weight: 1
        $x_1_4 = "FILE ENCRYPTED BY KELLY" wide //weight: 1
        $x_1_5 = "\\Leen.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LockyCrypt_PB_2147787292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockyCrypt.PB!MTB"
        threat_id = "2147787292"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locky" wide //weight: 1
        $x_1_2 = "readme-locky.txt" wide //weight: 1
        $x_1_3 = "Files has been encrypted with locky" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

