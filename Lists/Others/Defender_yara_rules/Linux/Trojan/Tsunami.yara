rule Trojan_Linux_Tsunami_B_2147814703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Tsunami.B!xp"
        threat_id = "2147814703"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KQRIQRLQRLQRAQRLQRL" ascii //weight: 1
        $x_1_2 = "fQRaQRkQReQRnQRaQRmQRe" ascii //weight: 1
        $x_1_3 = "GQREQRTQRSQRPQROQROQRFQRS" ascii //weight: 1
        $x_1_4 = "QRBQROQRTQRS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

