rule Backdoor_AndroidOS_Dingwe_A_2147755482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Dingwe.A!MTB"
        threat_id = "2147755482"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Dingwe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mnt/sdcard/Download/update.apk" ascii //weight: 1
        $x_1_2 = "/Filesend/upload_file" ascii //weight: 1
        $x_1_3 = "/Commands/delete_comm" ascii //weight: 1
        $x_1_4 = "com.connect" ascii //weight: 1
        $x_1_5 = "getWhatsApp_off" ascii //weight: 1
        $x_1_6 = "saveIncomingCall" ascii //weight: 1
        $x_1_7 = "getinboxsms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

