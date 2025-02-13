rule Backdoor_AndroidOS_Kmin_A_2147811434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Kmin.A!xp"
        threat_id = "2147811434"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Kmin"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/jx/res.apk" ascii //weight: 1
        $x_1_2 = "/jx/update.apk" ascii //weight: 1
        $x_1_3 = "Lcom/jx/ad/BootSmsReceiverService$SmsReceiver" ascii //weight: 1
        $x_1_4 = "com.jx.ad.ADService.Run" ascii //weight: 1
        $x_1_5 = "HasInstall91panda" ascii //weight: 1
        $x_1_6 = "//su.5k3g.com/portal/m/c5/0.ashx" ascii //weight: 1
        $x_1_7 = "//www.5j5l.com/ThemeDowner/91pandahome2.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

