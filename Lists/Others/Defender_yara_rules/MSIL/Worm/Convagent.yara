rule Worm_MSIL_Convagent_KK_2147971638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Convagent.KK!MTB"
        threat_id = "2147971638"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "UTFsync\\inf_data" ascii //weight: 5
        $x_4_2 = "CreateLnk" ascii //weight: 4
        $x_3_3 = "USBLNK" ascii //weight: 3
        $x_2_4 = "already infected!" ascii //weight: 2
        $x_1_5 = "blue3.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

