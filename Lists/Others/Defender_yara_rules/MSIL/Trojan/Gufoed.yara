rule Trojan_MSIL_Gufoed_A_2147846914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gufoed.A!MTB"
        threat_id = "2147846914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gufoed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Discord.gg/suckguard_" ascii //weight: 2
        $x_2_2 = "costura.discordmessenger.dll.compressed" ascii //weight: 2
        $x_2_3 = "antiblacklist" ascii //weight: 2
        $x_2_4 = "anticheck" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

