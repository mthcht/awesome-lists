rule Trojan_AndroidOS_SanDar_B_2147816132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SanDar.B!MTB"
        threat_id = "2147816132"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SanDar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/ka/longevity/service/RemoteService;" ascii //weight: 1
        $x_1_2 = {67 62 77 68 61 74 73 61 70 70 2e 64 6f 77 6e 6c 6f 61 64 2f [0-32] 61 70 70 2f 61 6e 64 72 6f 69 64 2f 61 70 6b}  //weight: 1, accuracy: Low
        $x_1_3 = "launchUnknownAppSources" ascii //weight: 1
        $x_1_4 = "collectNotifyInfo" ascii //weight: 1
        $x_1_5 = "installApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

