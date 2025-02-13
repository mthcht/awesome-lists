rule TrojanClicker_MSIL_Peadclik_A_2147683555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Peadclik.A"
        threat_id = "2147683555"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Peadclik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://adf.ly/" wide //weight: 1
        $x_1_2 = "Getkilled" wide //weight: 1
        $x_1_3 = "/platform:x86 /target:winexe" wide //weight: 1
        $x_1_4 = "ClickLinks" ascii //weight: 1
        $x_1_5 = "AddStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

