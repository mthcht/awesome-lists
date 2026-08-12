rule TrojanDropper_MSIL_AusterePurlin_C_2147975419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AusterePurlin.C!dha"
        threat_id = "2147975419"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AusterePurlin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tvsabp.rkr.rgnqch" ascii //weight: 1
        $x_1_2 = "-erfHxfnGrgnqcHzbbM" ascii //weight: 1
        $x_1_3 = "rgnqch\\avo\\zbbM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_MSIL_AusterePurlin_ASM_2147975772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AusterePurlin.ASM!MTB"
        threat_id = "2147975772"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AusterePurlin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 04 2b 6c 00 09 11 04 93 1f 61 32 0d 09 11 04 93 1f 7a fe 02 16 fe 01 2b 01 16 13 05 11 05 2c 17 09 11 04 09 11 04 93 1f 61 59 1f 0d 58 1f 1a 5d 1f 61 58 d1 9d}  //weight: 1, accuracy: High
        $x_1_2 = "TASK_LOGON_INTERACTIVE_TOKEN" ascii //weight: 1
        $x_1_3 = "TASK_ACTION_EXEC" ascii //weight: 1
        $x_1_4 = "TASK_CREATE_OR_UPDATE" ascii //weight: 1
        $x_1_5 = "TASK_INSTANCES_IGNORE_NEW" ascii //weight: 1
        $x_1_6 = "TASK_TRIGGER_DAILY" ascii //weight: 1
        $x_3_7 = "tvsabp.rkr.rgnqch" ascii //weight: 3
        $x_2_8 = "yzk.tvsabPrgnqcHyyq.erxpruPrgnqcH" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_AusterePurlin_D_2147975993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AusterePurlin.D!dha"
        threat_id = "2147975993"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AusterePurlin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 09 11 04 93 1f 61 32 0d 09 11 04 93 1f 7a fe 02 16 fe 01 2b 01 16 13 05}  //weight: 1, accuracy: High
        $x_1_2 = {09 11 04 09 11 04 93 1f 61 59 1f 0d 58 1f 1a 5d 1f 61 58 d1 9d 2b 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

