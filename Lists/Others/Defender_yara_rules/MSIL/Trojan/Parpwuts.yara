rule Trojan_MSIL_Parpwuts_C_2147670641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Parpwuts.C"
        threat_id = "2147670641"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Parpwuts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "340"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "Dede.Hoko.resources" ascii //weight: 200
        $x_100_2 = {00 69 55 47 6f 43 54 75 6e 71 6c 59 52 44 63 59 77 6a 5a 6b 6b 56 6c 59 00}  //weight: 100, accuracy: High
        $x_20_3 = "gPHsZQKVHpENCgBRMKnQAUW" wide //weight: 20
        $x_20_4 = "ruvcrqHjwmQgYcnKlBINcbT" wide //weight: 20
        $x_20_5 = "jhiqjFwIqYKVgwbjvPYiHBp" wide //weight: 20
        $x_20_6 = "MOXaLTRgqCIwvrUIbfM" ascii //weight: 20
        $x_20_7 = "PbadfNkAPMlPnNpwWjSCBPeOm" ascii //weight: 20
        $x_20_8 = "MYwbmOOBWCrjATQkBwUkWGj" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 1 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

