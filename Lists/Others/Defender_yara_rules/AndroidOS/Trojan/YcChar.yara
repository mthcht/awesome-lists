rule Trojan_AndroidOS_YcChar_A_2147794664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/YcChar.A!MTB"
        threat_id = "2147794664"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "YcChar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yccharge" ascii //weight: 1
        $x_1_2 = "/y/game.jsp?chargepara=" ascii //weight: 1
        $x_1_3 = "/item/face.php" ascii //weight: 1
        $x_1_4 = "/poker/pay/face.php" ascii //weight: 1
        $x_1_5 = "/userplatform/pay/page/" ascii //weight: 1
        $x_1_6 = "platform.handsmart.mobi" ascii //weight: 1
        $x_1_7 = "Init SMS Observer" ascii //weight: 1
        $x_1_8 = "mmsc.monternet.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

