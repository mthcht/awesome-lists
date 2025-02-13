rule Backdoor_AndroidOS_Levida_B_2147836810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Levida.B!MTB"
        threat_id = "2147836810"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Levida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/sl/loader" ascii //weight: 1
        $x_1_2 = "com.sl.update.SelfUpdate" ascii //weight: 1
        $x_1_3 = "com.sl.admin.SLDeviceAdminReceiver" ascii //weight: 1
        $x_1_4 = "ads.SlickAdActivity" ascii //weight: 1
        $x_1_5 = "getClassLoader" ascii //weight: 1
        $x_1_6 = "SLSDK.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Levida_A_2147836811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Levida.A!MTB"
        threat_id = "2147836811"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Levida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BackDoorInfo" ascii //weight: 1
        $x_1_2 = "com.sl.backdoor" ascii //weight: 1
        $x_1_3 = "slickurl" ascii //weight: 1
        $x_1_4 = "carrierserv/upload_data" ascii //weight: 1
        $x_1_5 = "getFakeJSON" ascii //weight: 1
        $x_1_6 = "getBackDoor" ascii //weight: 1
        $x_1_7 = "getTimeFromFirstInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

