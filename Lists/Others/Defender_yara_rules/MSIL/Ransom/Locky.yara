rule Ransom_MSIL_Locky_DSA_2147761632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Locky.DSA!MTB"
        threat_id = "2147761632"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "file-recovery-instructions.html" ascii //weight: 1
        $x_1_2 = "Your Files Have Been Encrypted By Zero-day Virus" ascii //weight: 1
        $x_1_3 = "The only way to recover your files is to pay .1 Bitcoins" ascii //weight: 1
        $x_1_4 = "For Help email: help@zerodaysample2018.net" ascii //weight: 1
        $x_1_5 = "Bitcoin wallet: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" ascii //weight: 1
        $x_1_6 = "WE APOLOGIZE BUT YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_MSIL_Locky_SG_2147906457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Locky.SG!MTB"
        threat_id = "2147906457"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 7e aa 00 00 04 11 04 7e 70 00 00 04 11 04 28 23 01 00 06 28 13 02 00 06 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

