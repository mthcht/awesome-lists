rule Trojan_MSIL_VeeraStealer_SMW_2147982022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VeeraStealer.SMW!MTB"
        threat_id = "2147982022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VeeraStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INJECT FAILED" ascii //weight: 1
        $x_1_2 = "payload.js" ascii //weight: 1
        $x_1_3 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
        $x_1_4 = "Passwords/passwords.txt" ascii //weight: 1
        $x_1_5 = "Wifi/wifi.txt" ascii //weight: 1
        $x_1_6 = "persistence: run key armed" ascii //weight: 1
        $x_1_7 = "VeeraApp.MainForm+<HarvestAll>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

