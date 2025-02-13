rule Ransom_MSIL_Crjoker_2147742216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crjoker"
        threat_id = "2147742216"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crjoker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "M{on{ey {geo{rg{e" wide //weight: 1
        $x_1_2 = "_Dan_g_er_ou_s_ Fr_e_sh" wide //weight: 1
        $x_1_3 = "Service quWheneverAmericaick" wide //weight: 1
        $x_1_4 = "QuicklyLive.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

