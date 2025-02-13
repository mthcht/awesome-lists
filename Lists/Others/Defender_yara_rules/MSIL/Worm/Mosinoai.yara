rule Worm_MSIL_Mosinoai_A_2147686296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mosinoai.A"
        threat_id = "2147686296"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mosinoai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Botkiller" ascii //weight: 1
        $x_1_2 = "antiSandboxie" ascii //weight: 1
        $x_1_3 = "StartRuskill" ascii //weight: 1
        $x_1_4 = "ARME flood on" wide //weight: 1
        $x_1_5 = "Slowloris flood on" wide //weight: 1
        $x_1_6 = " USB LNK spread on" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

