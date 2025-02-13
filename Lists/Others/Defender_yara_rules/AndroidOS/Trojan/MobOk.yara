rule Trojan_AndroidOS_MobOk_H_2147925739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MobOk.H"
        threat_id = "2147925739"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MobOk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "strategy/api/v1/apk/upload" ascii //weight: 2
        $x_2_2 = "trace.glk6opk.com" ascii //weight: 2
        $x_2_3 = "Smart_Link_Wait_Time_out" ascii //weight: 2
        $x_2_4 = "updateUnWifiCfg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

