rule Ransom_AndroidOS_Congur_A_2147753420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Congur.A"
        threat_id = "2147753420"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Congur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.h.s" ascii //weight: 2
        $x_2_2 = "Lcom/h/DU;" ascii //weight: 2
        $x_2_3 = "Lcom/h/MyAdmin;" ascii //weight: 2
        $x_1_4 = "Lcom/h/bbb" ascii //weight: 1
        $x_1_5 = "c29fe56fa59ab0db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_AndroidOS_Congur_B_2147787639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Congur.B"
        threat_id = "2147787639"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Congur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "theBeginTimeToFinish" ascii //weight: 2
        $x_2_2 = "keyTouthInt" ascii //weight: 2
        $x_1_3 = "tk.jianmo.lockphone" ascii //weight: 1
        $x_1_4 = "com.yc.lovelock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_AndroidOS_Congur_B_2147831443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Congur.B!MTB"
        threat_id = "2147831443"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Congur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com/dulang/clock/BootBroadcastReceiver" ascii //weight: 3
        $x_2_2 = "ClockService" ascii //weight: 2
        $x_1_3 = "val$psw" ascii //weight: 1
        $x_1_4 = "setOnClickListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_AndroidOS_Congur_C_2147833566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Congur.C!MTB"
        threat_id = "2147833566"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Congur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 00 1a 01 1f 01 6e 20 ?? ?? 10 00 0a 00 38 00 18 00 6e 10 ?? ?? 02 00 22 00 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 21 0f 00 54 41 07 00 44 01 01 00 87 11 13 02 2d 00 37 21 07 00 13 00 a6 ff 67 00 1b 00}  //weight: 1, accuracy: High
        $x_1_3 = {0c 02 70 20 ?? ?? 20 00 38 04 05 00 6e 10 ?? ?? 04 00 38 03 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

