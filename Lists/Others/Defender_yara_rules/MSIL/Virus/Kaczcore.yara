rule Virus_MSIL_Kaczcore_2147964793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:MSIL/Kaczcore"
        threat_id = "2147964793"
        type = "Virus"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kaczcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KaczCORE_Virus" ascii //weight: 1
        $x_1_2 = "Kontakt DC: kaczkayt10" ascii //weight: 1
        $x_1_3 = "{\"files\":{\"haslo.txt\":{\"content\":\"START\"}}}" ascii //weight: 1
        $x_1_4 = "Maszyna:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

