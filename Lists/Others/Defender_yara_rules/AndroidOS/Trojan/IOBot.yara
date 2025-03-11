rule Trojan_AndroidOS_IOBot_A_2147914094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/IOBot.A!MTB"
        threat_id = "2147914094"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "IOBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.spacex.mmobile" ascii //weight: 5
        $x_1_2 = "activeInjectAppPackage" ascii //weight: 1
        $x_1_3 = "activeInjectLogId" ascii //weight: 1
        $x_1_4 = "HIDDEN_VNC" ascii //weight: 1
        $x_1_5 = "spacextraffic.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_IOBot_PH_2147919997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/IOBot.PH"
        threat_id = "2147919997"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "IOBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/app/8c5e1489e530dd6cd39b" ascii //weight: 1
        $x_1_2 = "wss://api.spacexmmobile.com/ws/mobile/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_IOBot_B_2147921855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/IOBot.B!MTB"
        threat_id = "2147921855"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "IOBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.kr.mt" ascii //weight: 2
        $x_1_2 = "IOBot.getPhoneNumber" ascii //weight: 1
        $x_1_3 = "IOBot.getPhoneModel" ascii //weight: 1
        $x_1_4 = "IOBot.getScreenStatus" ascii //weight: 1
        $x_1_5 = "services.AppAccessibilityService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_IOBot_C_2147935675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/IOBot.C!MTB"
        threat_id = "2147935675"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "IOBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOBot.getBatteryLevel" ascii //weight: 1
        $x_1_2 = "IOBot.getPhoneModel" ascii //weight: 1
        $x_1_3 = "IOBot.getPhoneNumber" ascii //weight: 1
        $x_1_4 = "IOBot.getScreenStatus" ascii //weight: 1
        $x_1_5 = "hidden_vnc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

