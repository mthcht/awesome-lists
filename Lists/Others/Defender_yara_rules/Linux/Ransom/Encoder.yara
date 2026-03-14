rule Ransom_Linux_Encoder_PA_2147964760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Encoder.PA!MTB"
        threat_id = "2147964760"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".systemfile" ascii //weight: 1
        $x_1_2 = "file is encrypted" ascii //weight: 1
        $x_3_3 = "%s/_FILES_ENCRYPTED_README.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

