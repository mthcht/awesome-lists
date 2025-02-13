rule Trojan_AndroidOS_VaneSms_A_2147647897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/VaneSms.A"
        threat_id = "2147647897"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "VaneSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phone.indexOf(aa[i])=" ascii //weight: 1
        $x_1_2 = "$Evan.BackgroundSMS.BootService.class" ascii //weight: 1
        $x_1_3 = "adsms.itodo.cn/Report/SepkfConfirm.aspx?spid=" ascii //weight: 1
        $x_1_4 = "GP.HareCodeRegNum[t]=" ascii //weight: 1
        $x_1_5 = "IsSepChannelSended=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

