rule Worm_MSIL_Aninisom_A_2147666408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Aninisom.A"
        threat_id = "2147666408"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aninisom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "255"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "[USB]: Completed LNK spread on" wide //weight: 100
        $x_100_2 = "[FACEBOOK]: Spread module activated" wide //weight: 100
        $x_20_3 = "[PERSISTENCE]: Registry key was replaced" wide //weight: 20
        $x_20_4 = "[RUSKILL]: Outgoing connection detected" wide //weight: 20
        $x_20_5 = "[BOTKILLER]: Removing registry" wide //weight: 20
        $x_5_6 = "[UPDATE]: Bot file updated." wide //weight: 5
        $x_5_7 = ".fbspread" wide //weight: 5
        $x_5_8 = "[UDP]: Flooding" wide //weight: 5
        $x_5_9 = "Executed file with Ruskill" wide //weight: 5
        $x_3_10 = "[LAYER7]: Flooding " wide //weight: 3
        $x_3_11 = "[APACHE-RME]: " wide //weight: 3
        $x_3_12 = "[SLOWLORIS]: " wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_20_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_100_*) and 2 of ($x_20_*) and 3 of ($x_5_*))) or
            ((2 of ($x_100_*) and 3 of ($x_20_*))) or
            (all of ($x*))
        )
}

