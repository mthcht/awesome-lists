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

