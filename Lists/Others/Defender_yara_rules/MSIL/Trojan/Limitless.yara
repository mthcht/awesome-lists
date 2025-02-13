rule Trojan_MSIL_Limitless_A_2147683966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Limitless.A"
        threat_id = "2147683966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Limitless"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Limitless Logger : : Recovery Records" wide //weight: 2
        $x_1_2 = "/c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /f /v" wide //weight: 1
        $x_1_3 = "Sending Skype Message..." wide //weight: 1
        $x_1_4 = "[::-- Steam Usern" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

