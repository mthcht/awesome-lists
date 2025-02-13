rule Trojan_AndroidOS_DroidDeluxe_A_2147649071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidDeluxe.A"
        threat_id = "2147649071"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidDeluxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.pocketluxus.recovery/password" ascii //weight: 1
        $x_1_2 = "FAKE_DOMAIN_HASH" ascii //weight: 1
        $x_1_3 = "BUSY_FILE" ascii //weight: 1
        $x_1_4 = "UA-19670793-1" ascii //weight: 1
        $x_1_5 = "__##GOOGLEPAGEVIEW##__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

