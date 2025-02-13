rule Trojan_AndroidOS_Rediassi_A_2147812198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rediassi.A!xp"
        threat_id = "2147812198"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rediassi"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://uploaderis.ru/" ascii //weight: 2
        $x_1_2 = "//button.dekel.ru/." ascii //weight: 1
        $x_1_3 = "isActiveNetworkMetered" ascii //weight: 1
        $x_1_4 = "com.rockastar." ascii //weight: 1
        $x_1_5 = "MonitorActivity" ascii //weight: 1
        $x_1_6 = "loadInBackground" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

