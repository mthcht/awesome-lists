rule Ransom_MSIL_FancyLocker_PAA_2147786769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FancyLocker.PAA!MTB"
        threat_id = "2147786769"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FancyLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware" ascii //weight: 1
        $x_1_2 = "\\README.FancyLeaks.txt" wide //weight: 1
        $x_1_3 = "have been encrypted!" wide //weight: 1
        $x_1_4 = "FancyLocker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

