rule Trojan_MSIL_CookieStealer_A_2147965561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CookieStealer.A!AMTB"
        threat_id = "2147965561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CookieStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StealWallets" ascii //weight: 1
        $x_1_2 = "[*] Stealing Telegram sessions..." ascii //weight: 1
        $x_1_3 = "AppStealers" ascii //weight: 1
        $x_1_4 = "Akachu | t.me/ak4chu" ascii //weight: 1
        $x_1_5 = "CookieStealer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

