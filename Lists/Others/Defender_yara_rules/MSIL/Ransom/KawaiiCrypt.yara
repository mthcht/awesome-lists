rule Ransom_MSIL_KawaiiCrypt_PA_2147830940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KawaiiCrypt.PA!MTB"
        threat_id = "2147830940"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KawaiiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your system has been encrypted!" wide //weight: 1
        $x_1_2 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 [0-16] 62 79 20 4b 41 57 41 49 49 20 72 61 6e 73 6f 6d 77 61 72 65}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Anime.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_KawaiiCrypt_ST_2147830979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KawaiiCrypt.ST!MTB"
        threat_id = "2147830979"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KawaiiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bc1qcqr5ffr4fqd3a8e9jv6dwfkm54p5zu43mp69vs" ascii //weight: 1
        $x_1_2 = "KAWAII ransomware" ascii //weight: 1
        $x_1_3 = "have been encrypted" ascii //weight: 1
        $x_1_4 = "decryption key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

