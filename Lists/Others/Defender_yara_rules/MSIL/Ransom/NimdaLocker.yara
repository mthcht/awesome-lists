rule Ransom_MSIL_NimdaLocker_PAA_2147787194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NimdaLocker.PAA!MTB"
        threat_id = "2147787194"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NimdaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/c del NimdaLocker.exe" wide //weight: 5
        $x_1_2 = "private information have been acquired!" wide //weight: 1
        $x_1_3 = "Ransomware.Functions.resources" ascii //weight: 1
        $x_1_4 = "Encryption Finished!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

