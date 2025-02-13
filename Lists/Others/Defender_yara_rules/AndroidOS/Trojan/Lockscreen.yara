rule Trojan_AndroidOS_Lockscreen_B_2147744797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Lockscreen.B!MTB"
        threat_id = "2147744797"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/bendel_software/anlocker" ascii //weight: 1
        $x_1_2 = "LockerService$100000000" ascii //weight: 1
        $x_1_3 = "adrt$enabled" ascii //weight: 1
        $x_1_4 = "unclock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Lockscreen_E_2147850583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Lockscreen.E"
        threat_id = "2147850583"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Lockscreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.qihoo.jiagutracker" ascii //weight: 1
        $x_1_2 = "deleteFilesStartWithGivenString" ascii //weight: 1
        $x_1_3 = "31f68eaf3ac13d70869a7a676f12f8caa2434433af69eb7ec2f0921299e8337c" ascii //weight: 1
        $x_1_4 = "end get packageName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

