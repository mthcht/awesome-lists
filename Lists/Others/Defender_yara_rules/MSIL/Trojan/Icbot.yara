rule Trojan_MSIL_Icbot_A_2147711066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Icbot.A!bit"
        threat_id = "2147711066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Icbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!killbot" wide //weight: 1
        $x_1_2 = "!turn on monitor" wide //weight: 1
        $x_1_3 = "record recsound" wide //weight: 1
        $x_1_4 = "!hack dns <ip> <url>" wide //weight: 1
        $x_1_5 = "netsh firewall set opmode disable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

