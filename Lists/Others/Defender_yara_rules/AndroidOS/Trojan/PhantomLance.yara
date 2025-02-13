rule Trojan_AndroidOS_PhantomLance_A_2147783406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PhantomLance.A"
        threat_id = "2147783406"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PhantomLance"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".MS_ACTIVITY" ascii //weight: 2
        $x_2_2 = "xpoihhdecvdd" ascii //weight: 2
        $x_2_3 = "DROP TABLE IF EXISTS idhgxonyg9yhn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

