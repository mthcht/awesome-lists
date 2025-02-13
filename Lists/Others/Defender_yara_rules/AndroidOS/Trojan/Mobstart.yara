rule Trojan_AndroidOS_Mobstart_A_2147904632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobstart.A!MTB"
        threat_id = "2147904632"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobstart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.hzdi.happybird" ascii //weight: 5
        $x_5_2 = "com.mobistartapp.coderoute.hzpermispro.ar" ascii //weight: 5
        $x_1_3 = "PushAdActivity" ascii //weight: 1
        $x_1_4 = "PushNotifRouterActivity" ascii //weight: 1
        $x_1_5 = "remoteMessage" ascii //weight: 1
        $x_1_6 = "PubActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

