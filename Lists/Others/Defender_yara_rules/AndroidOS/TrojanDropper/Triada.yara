rule TrojanDropper_AndroidOS_Triada_A_2147779367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Triada.A!MTB"
        threat_id = "2147779367"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.slacken.work.mischie" ascii //weight: 1
        $x_1_2 = "startDetectionAlarm" ascii //weight: 1
        $x_1_3 = "Ti92R_37Tet_AiTia" ascii //weight: 1
        $x_1_4 = "ReSetAdvertCalTime" ascii //weight: 1
        $x_1_5 = "m_bDeadSwitch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Triada_B_2147779595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Triada.B!MTB"
        threat_id = "2147779595"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Lcom/main/w2c6c7/m5i6an9/" ascii //weight: 2
        $x_1_2 = {73 73 6b 30 31 35 2d 79 6d 32 0a 00 04 00 2d 02 00 2d 02 00}  //weight: 1, accuracy: Low
        $x_1_3 = "r2e2ad2D2a2ta" ascii //weight: 1
        $x_1_4 = "Lcom/zcoup/base/core/ZcoupSDK;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

