rule DDoS_MSIL_Ormerga_A_2147718550_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:MSIL/Ormerga.A!bit"
        threat_id = "2147718550"
        type = "DDoS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ormerga"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ImHere" ascii //weight: 2
        $x_2_2 = "GetAttack" ascii //weight: 2
        $x_2_3 = "\\temp\\dIIhost.exe" wide //weight: 2
        $x_1_4 = "/bot_data/server_list/server" wide //weight: 1
        $x_1_5 = "bot/output" wide //weight: 1
        $x_1_6 = "/bot_data/ddos_list/ddos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

