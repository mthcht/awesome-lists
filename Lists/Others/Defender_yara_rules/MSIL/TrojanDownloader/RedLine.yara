rule TrojanDownloader_MSIL_Redline_CL_2147838672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Redline.CL!MTB"
        threat_id = "2147838672"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "import.dalvik.annotation.optimization.module6" ascii //weight: 5
        $x_1_2 = "HashCollisionThresholdTYPEDESC" ascii //weight: 1
        $x_1_3 = "KoreanCalendarHasRelatedActivityID" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "op_Equality" ascii //weight: 1
        $x_1_6 = "Setup for Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

