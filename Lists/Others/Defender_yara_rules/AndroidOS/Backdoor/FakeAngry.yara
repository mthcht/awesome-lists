rule Backdoor_AndroidOS_FakeAngry_A_2147811433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/FakeAngry.A!xp"
        threat_id = "2147811433"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "FakeAngry"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.cmcc.mobilevideo" ascii //weight: 1
        $x_1_2 = "cmcc_dynamic_login" ascii //weight: 1
        $x_1_3 = "cmcc_static_login" ascii //weight: 1
        $x_1_4 = "/mnt/sdcard-ext/.mobilevideo/download/" ascii //weight: 1
        $x_1_5 = "/libtmpcplayer.so" ascii //weight: 1
        $x_1_6 = "ophoneV2/orderList.ophone" ascii //weight: 1
        $x_1_7 = "://c2.cmvideo.cn/ugcapp/uploadFile/=" ascii //weight: 1
        $x_1_8 = "/ugcapp/uploadFile/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

