rule Trojan_AndroidOS_AVPasser_A_2147781964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AVPasser.A!MTB"
        threat_id = "2147781964"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AVPasser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6d 20 2d 72 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f [0-6] 2e 61 70 6b}  //weight: 1, accuracy: Low
        $x_1_2 = "rm -r /system/su" ascii //weight: 1
        $x_1_3 = "chmod 777 /system/xbin/su" ascii //weight: 1
        $x_1_4 = "am force-stop com.antivirus" ascii //weight: 1
        $x_1_5 = "uninstall apk" ascii //weight: 1
        $x_1_6 = "open call record function" ascii //weight: 1
        $x_1_7 = "CallLogObserver" ascii //weight: 1
        $x_1_8 = "Camera take_pic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

