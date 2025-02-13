rule Ransom_MSIL_Yikes_PAA_2147796531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Yikes.PAA!MTB"
        threat_id = "2147796531"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yikes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomwarePOC" ascii //weight: 1
        $x_1_2 = "ENCRYPTED_FILE_EXTENSION" ascii //weight: 1
        $x_1_3 = "your files have been encrypted" ascii //weight: 1
        $x_1_4 = "\\___RECOVER__FILES__.yikes.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

