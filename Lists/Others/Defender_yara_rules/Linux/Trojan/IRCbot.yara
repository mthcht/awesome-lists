rule Trojan_Linux_IRCbot_A_2147814699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/IRCbot.A!xp"
        threat_id = "2147814699"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "IRCbot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KQRIQRLQRLQRAQRLQRL" ascii //weight: 1
        $x_1_2 = "GQREQRTQRSQRPQROQROQRFQRS" ascii //weight: 1
        $x_1_3 = "QRBQROQRTQRS" ascii //weight: 1
        $x_1_4 = "fQRaQRkQReQRnQRaQRmQRe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

