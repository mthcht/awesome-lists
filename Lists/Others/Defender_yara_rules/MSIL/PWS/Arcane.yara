rule PWS_MSIL_Arcane_YA_2147734997_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Arcane.YA!MTB"
        threat_id = "2147734997"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Arcane"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "Arcane Stealer" wide //weight: 9
        $x_1_2 = "\\Google\\Chrome\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_3 = "\\Opera Software\\Opera Stable\\Cookies" wide //weight: 1
        $x_1_4 = "\\Kometa\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_5 = "\\Orbitum\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_6 = "\\Comodo\\Dragon\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_7 = "\\Amigo\\User\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_8 = "\\Torch\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_9 = "\\Browsers\\Cookies\\Cookies_{0}.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

