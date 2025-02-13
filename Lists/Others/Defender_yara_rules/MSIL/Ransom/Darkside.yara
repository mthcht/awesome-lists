rule Ransom_MSIL_Darkside_SK_2147892444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Darkside.SK!MTB"
        threat_id = "2147892444"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkside"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "But you can restore everything by purchasing a special program from us - universal decryptor" ascii //weight: 1
        $x_1_2 = "DO NOT MODIFY or try to RECOVER any files yourself. We WILL NOT be able to RESTORE them." ascii //weight: 1
        $x_1_3 = "We guarantee to decrypt one file for free. Go to the site and contact us." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

