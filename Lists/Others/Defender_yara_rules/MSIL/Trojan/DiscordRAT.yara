rule Trojan_MSIL_DiscordRAT_RDA_2147839819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordRAT.RDA!MTB"
        threat_id = "2147839819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cc12258f-af24-4773-a8e3-45d365bcbde9" ascii //weight: 1
        $x_1_2 = "Discord rat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordRAT_RDB_2147902244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordRAT.RDB!MTB"
        threat_id = "2147902244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discord rat" ascii //weight: 1
        $x_1_2 = "DisableDefender" ascii //weight: 1
        $x_1_3 = "uacbypass" ascii //weight: 1
        $x_1_4 = "DisableFirewall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

