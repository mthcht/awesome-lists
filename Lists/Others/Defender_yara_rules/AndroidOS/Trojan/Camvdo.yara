rule Trojan_AndroidOS_Camvdo_A_2147779666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Camvdo.A!MTB"
        threat_id = "2147779666"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Camvdo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.chagall.screenshot" ascii //weight: 1
        $x_1_2 = "com.chagall.GPS_data" ascii //weight: 1
        $x_2_3 = "camvdo=camvdo" ascii //weight: 2
        $x_1_4 = ">smsMoniter=" ascii //weight: 1
        $x_1_5 = "callMoniter" ascii //weight: 1
        $x_1_6 = "173.249.50.34-shareboxs.net" ascii //weight: 1
        $x_1_7 = "/._HAATNECS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

