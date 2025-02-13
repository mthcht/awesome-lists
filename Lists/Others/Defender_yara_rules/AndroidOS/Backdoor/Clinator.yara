rule Backdoor_AndroidOS_Clinator_A_2147760273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Clinator.A!MTB"
        threat_id = "2147760273"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Clinator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {15 00 00 00 12 12 62 00 ?? ?? 12 01 6e 30 ?? ?? 10 02 0a 00 38 00 0a 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 10 ?? ?? 00 00 0f 02 0d 00 28 fe}  //weight: 1, accuracy: Low
        $x_1_2 = "InetAddress" ascii //weight: 1
        $x_1_3 = "com/ivengo/ads" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

