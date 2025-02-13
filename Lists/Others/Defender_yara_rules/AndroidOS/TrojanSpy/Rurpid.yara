rule TrojanSpy_AndroidOS_Rurpid_A_2147833100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Rurpid.A!MTB"
        threat_id = "2147833100"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Rurpid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "de/rub/syssec" ascii //weight: 1
        $x_1_2 = "com.some.where.lock.static" ascii //weight: 1
        $x_1_3 = "prepareSend" ascii //weight: 1
        $x_1_4 = "sendData" ascii //weight: 1
        $x_1_5 = "127.0.0.1:53471" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

