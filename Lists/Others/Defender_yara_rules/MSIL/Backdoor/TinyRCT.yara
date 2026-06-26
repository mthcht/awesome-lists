rule Backdoor_MSIL_TinyRCT_B_2147972441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/TinyRCT.B!AMTB"
        threat_id = "2147972441"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TinyRCT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://45.32.113.172/Kf8RyF1G" ascii //weight: 1
        $x_1_2 = "ExecuteCommandAsync" ascii //weight: 1
        $x_1_3 = "GetDirAndFile" ascii //weight: 1
        $x_1_4 = "GetTaskAsync" ascii //weight: 1
        $x_1_5 = "ResloveData" ascii //weight: 1
        $x_1_6 = "ScreenShot" ascii //weight: 1
        $x_1_7 = "Serverkey" ascii //weight: 1
        $x_1_8 = "TinyRCT" ascii //weight: 1
        $x_1_9 = "virtual" ascii //weight: 1
        $x_1_10 = "vmware" ascii //weight: 1
        $x_1_11 = "hyper" ascii //weight: 1
        $x_1_12 = "SayHi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

