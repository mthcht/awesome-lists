rule Trojan_MacOS_BeaverTail_A_2147917157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/BeaverTail.A!MTB"
        threat_id = "2147917157"
        type = "Trojan"
        platform = "MacOS: "
        family = "BeaverTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 1c 85 c0 74 09 f0 ff 0f 75 13 48 8b 7d d8 be 02 00 00 00 ba 08 00 00 00 e8 91 4e 00 00 41 c7 86 98 00 00 00 02 00 00 00 48 8b 1d 39 f0 0a 00 48 89 5d d8 48 8d 3d 02 60 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 5d b0 48 89 df 48 8d 35 66 50 00 00 ba 0b 00 00 00 e8 52 3e 00 00 48 8d 7d 98 48 89 de e8 58 3e 00 00 48 8b 7d b0 8b 07 83 f8 ff 74 1c 85 c0 74 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

