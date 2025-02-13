rule Trojan_MacOS_Lazarus_A_2147899717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Lazarus.A!MTB"
        threat_id = "2147899717"
        type = "Trojan"
        platform = "MacOS: "
        family = "Lazarus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c8 02 19 4a e9 02 14 8b 28 81 00 39 1f 1d 00 72 20 fe ff 54 e9 03 15 aa f5 03 08 aa 08 1d 00 12 29 1d 00 12 2a 09 c8 1a 48 a5 08 1b e9 03 15 aa 48 ff ff 35 e8 ff ff 17 e0 03 17 aa 6d 05 00 94 f7 03 00 aa ef ff ff 17}  //weight: 1, accuracy: High
        $x_1_2 = {f5 03 08 aa 08 1d 00 12 29 1d 00 12 2a 09 c8 1a 48 a5 08 1b e9 03 15 aa 48 ff ff 35}  //weight: 1, accuracy: High
        $x_1_3 = {c9 02 08 8b 0a 05 00 91 28 81 40 39 08 01 13 4a 28 81 00 39 e8 03 0a aa 9f 02 0a eb 21 ff ff 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

