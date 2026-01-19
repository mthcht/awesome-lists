rule Ransom_MSIL_Encoder_PC_2147958376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Encoder.PC!MTB"
        threat_id = "2147958376"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Encrypted:" wide //weight: 1
        $x_2_2 = {5c 52 61 78 78 6d 78 6d 78 6d 78 6d 5c [0-8] 5c [0-8] [0-8] 5c 52 61 78 78 6d 78 6d 78 6d 78 6d 2e 70 64 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Encoder_PD_2147958443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Encoder.PD!MTB"
        threat_id = "2147958443"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.txt" wide //weight: 1
        $x_1_2 = ".ransomeware" wide //weight: 1
        $x_2_3 = "YOUR FILES ARE ENCRYPTED" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Encoder_PE_2147961313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Encoder.PE!MTB"
        threat_id = "2147961313"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files have been encrypted with strongest" ascii //weight: 1
        $x_1_2 = "Your system32 will be damaged" wide //weight: 1
        $x_3_3 = "DO_NOT_OPEN_THE_FUCKIN_RANSOMWARE" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

