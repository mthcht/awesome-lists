rule Rogue_MSIL_Rustliver_223709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MSIL/Rustliver"
        threat_id = "223709"
        type = "Rogue"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rustliver"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "user_pref(\"security.warn_leaving_secure\", false);" wide //weight: 2
        $x_2_2 = "Browser_voice.wav" wide //weight: 2
        $x_1_3 = "Software\\SBS\\Safe_Browsing\\Activation" wide //weight: 1
        $x_1_4 = "Software\\Browser_security\\Activation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

