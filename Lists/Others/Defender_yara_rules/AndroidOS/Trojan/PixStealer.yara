rule Trojan_AndroidOS_PixStealer_A_2147794881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PixStealer.A"
        threat_id = "2147794881"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PixStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/gservice/autobot/Acessibilidade" ascii //weight: 5
        $x_1_2 = "Framework::AutoBot::Socket::Visualizar::SenClicked" ascii //weight: 1
        $x_1_3 = "valor" ascii //weight: 1
        $x_1_4 = "dxThread_Protect" ascii //weight: 1
        $x_1_5 = "<cmd>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

