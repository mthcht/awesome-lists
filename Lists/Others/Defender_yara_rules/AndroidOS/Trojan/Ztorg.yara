rule Trojan_AndroidOS_Ztorg_A_2147812484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ztorg.A!xp"
        threat_id = "2147812484"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ztorg"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.ddlions.thunder" ascii //weight: 1
        $x_2_2 = "com.kok.ddlions.frame.StartService" ascii //weight: 2
        $x_1_3 = "com.yeah.download.ACTION_DOWNLOAD_START" ascii //weight: 1
        $x_1_4 = ".blueskysz.com:9884/newservice/newbackDatas.action" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

