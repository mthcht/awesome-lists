rule Trojan_AndroidOS_ElegantRevoke_A_2147796410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ElegantRevoke.A"
        threat_id = "2147796410"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ElegantRevoke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vpnuser2" ascii //weight: 1
        $x_1_2 = "VpNu$3R" ascii //weight: 1
        $x_1_3 = "http://cdsa.xyz" ascii //weight: 1
        $x_1_4 = "Tap to get a better user experience Of Android" ascii //weight: 1
        $x_1_5 = "Screenshot Module is running." ascii //weight: 1
        $x_1_6 = "Api/IsRunAudioRecorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

