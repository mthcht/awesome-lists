rule Trojan_AndroidOS_Joye_A_2147833879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joye.A!MTB"
        threat_id = "2147833879"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "globalpayrecord/record/record.php" ascii //weight: 1
        $x_1_2 = "paydata=" ascii //weight: 1
        $x_1_3 = "smsCodeMessage" ascii //weight: 1
        $x_1_4 = "sendTextMessageMtk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

