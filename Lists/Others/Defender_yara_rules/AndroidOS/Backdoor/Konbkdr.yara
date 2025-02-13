rule Backdoor_AndroidOS_Konbkdr_A_2147767927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Konbkdr.A!MTB"
        threat_id = "2147767927"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Konbkdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lapp/project/appcheck/" ascii //weight: 2
        $x_2_2 = "up.php" ascii //weight: 2
        $x_1_3 = "install_apk" ascii //weight: 1
        $x_1_4 = "get_keylog" ascii //weight: 1
        $x_1_5 = "keylog.txt" ascii //weight: 1
        $x_1_6 = "sms_all.txt" ascii //weight: 1
        $x_1_7 = "phonecall.txt" ascii //weight: 1
        $x_1_8 = "TotalMsg.txt" ascii //weight: 1
        $x_1_9 = "CardInfo.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

