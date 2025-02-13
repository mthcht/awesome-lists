rule Trojan_MSIL_GameCheat_J_2147740802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GameCheat.J!ibt"
        threat_id = "2147740802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GameCheat"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Disable antivirus" wide //weight: 1
        $x_1_2 = "\\Device\\BattlEye" wide //weight: 1
        $x_1_3 = ".eurodir.ru" wide //weight: 1
        $x_1_4 = "vk.com/arma2oa_hack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

