rule Trojan_MSIL_Eskimo_A_2147690474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Eskimo.A"
        threat_id = "2147690474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eskimo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "7656119[0-9]{10}%7c%7c[A-F0-9]{40}" ascii //weight: 6
        $x_1_2 = {18 04 3d 04 38 04 46 04 38 04 30 04 3b 04 38 04 37 04 30 04 46 04 38 04 4f 04 20 00 44 04 30 04 39 04 3b 04 3e 04 32 04 2e 00 2e 00 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = "tradeoffer/new/?partner=" ascii //weight: 1
        $x_1_4 = "common,uncommon,rare,mythical,legendary,immortal" ascii //weight: 1
        $x_1_5 = "steamLogin" ascii //weight: 1
        $x_1_6 = "steamclient.dll" ascii //weight: 1
        $x_5_7 = "SteamSteal" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Eskimo_2147694142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Eskimo"
        threat_id = "2147694142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eskimo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SteamStealer." ascii //weight: 5
        $x_1_2 = "set_UserAgent" ascii //weight: 1
        $x_1_3 = "get_Keys" ascii //weight: 1
        $x_1_4 = "get_Item" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

