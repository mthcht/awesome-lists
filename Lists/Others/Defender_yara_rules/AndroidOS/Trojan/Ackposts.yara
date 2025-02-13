rule Trojan_AndroidOS_Ackposts_A_2147659443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ackposts.A"
        threat_id = "2147659443"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ackposts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "iQueryMissOrderCallback" ascii //weight: 2
        $x_2_2 = "v3fmhrp15" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ackposts_A_2147659443_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ackposts.A"
        threat_id = "2147659443"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ackposts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jackpostsss.heteml.jp/batterylong.php" ascii //weight: 1
        $x_1_2 = "has_phone_number" ascii //weight: 1
        $x_1_3 = "contact_id = ?" ascii //weight: 1
        $x_1_4 = "CommonDataKinds$Email" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

