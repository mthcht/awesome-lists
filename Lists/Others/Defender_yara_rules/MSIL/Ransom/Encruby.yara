rule Ransom_MSIL_Encruby_2147725763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Encruby"
        threat_id = "2147725763"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Encruby"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" wide //weight: 1
        $x_2_2 = "Black Ruby Decryptor" wide //weight: 2
        $x_2_3 = "HOW-TO-DECRYPT-FILES.txt" wide //weight: 2
        $x_2_4 = ".BlackRuby" wide //weight: 2
        $x_2_5 = "*** Any attempts to get back you files with the third-party tools can be fatal for your encrypted files ***" wide //weight: 2
        $x_6_6 = "TheBlackRuby@Protonmail.com" wide //weight: 6
        $x_6_7 = "19S7k3zHphKiYr85T25FnqdxizHcgmjoj1" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

