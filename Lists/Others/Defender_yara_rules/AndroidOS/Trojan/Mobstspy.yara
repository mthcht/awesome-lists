rule Trojan_AndroidOS_MobstSpy_B_2147840758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MobstSpy.B"
        threat_id = "2147840758"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MobstSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "moc.ppatratsibom.www//:ptth" ascii //weight: 2
        $x_2_2 = "/gcm_server_php/happy_bird/" ascii //weight: 2
        $x_2_3 = "isNotifClear" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

