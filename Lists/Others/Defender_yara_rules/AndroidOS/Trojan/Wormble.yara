rule Trojan_AndroidOS_Wormble_A_2147797797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wormble.A"
        threat_id = "2147797797"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wormble"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CRAP" ascii //weight: 2
        $x_2_2 = "Group_phone:" ascii //weight: 2
        $x_2_3 = "inside sendReply" ascii //weight: 2
        $x_2_4 = "naah" ascii //weight: 2
        $x_1_5 = "mobilestream.club/?netflix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

