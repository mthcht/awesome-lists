rule TrojanSpy_AndroidOS_Cosha_A_2147648273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cosha.A"
        threat_id = "2147648273"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cosha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IfRecieveAC" ascii //weight: 1
        $x_1_2 = ">>>>>>>>RecorderTask Construction Func" ascii //weight: 1
        $x_1_3 = "=AX360_Serv=" ascii //weight: 1
        $x_1_4 = "cooshare.com/careu/positionrecorder.asmx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_Cosha_A_2147831397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cosha.A!MTB"
        threat_id = "2147831397"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cosha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.anxin360.com/welcome/p.ashx?lat=" ascii //weight: 1
        $x_1_2 = "SendSMS" ascii //weight: 1
        $x_1_3 = "SMSSrv" ascii //weight: 1
        $x_1_4 = "V4SMSServ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

