rule Trojan_MSIL_DiscordRat_C_2147978616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordRat.C!MTB"
        threat_id = "2147978616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Release\\Discord rat.exe" ascii //weight: 1
        $x_1_2 = "Discord_rat.settings" ascii //weight: 1
        $x_1_3 = "Bot token" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

