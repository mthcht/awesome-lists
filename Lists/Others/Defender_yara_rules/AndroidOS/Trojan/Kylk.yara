rule Trojan_AndroidOS_Kylk_J_2147921648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kylk.J"
        threat_id = "2147921648"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kylk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CTDAdmRiver" ascii //weight: 2
        $x_2_2 = "com_pre_reg" ascii //weight: 2
        $x_2_3 = "dlac_lng" ascii //weight: 2
        $x_2_4 = "Dxld_app" ascii //weight: 2
        $x_2_5 = "reqCoaLoc" ascii //weight: 2
        $x_2_6 = "reqReceSms" ascii //weight: 2
        $x_2_7 = "WA_AUDIO_TIME_SEND" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

