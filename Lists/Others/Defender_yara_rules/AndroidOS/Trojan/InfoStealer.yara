rule Trojan_AndroidOS_Infostealer_AS_2147781385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Infostealer.AS!MTB"
        threat_id = "2147781385"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callLogs.LogsContentProvider/sms" ascii //weight: 1
        $x_1_2 = "recalc_sms" ascii //weight: 1
        $x_1_3 = "sms_out_tc_money" ascii //weight: 1
        $x_1_4 = "talk_duration" ascii //weight: 1
        $x_1_5 = "call_fee" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Infostealer_G_2147833664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Infostealer.G"
        threat_id = "2147833664"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wfhiahwfihwal.tk/hajman" ascii //weight: 2
        $x_2_2 = "ResumableSub_fm_MessageArrived" ascii //weight: 2
        $x_2_3 = "_sendlargesms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Infostealer_H_2147835420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Infostealer.H"
        threat_id = "2147835420"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "alroment.tk/t" ascii //weight: 2
        $x_2_2 = "ResumableSub_fm_MessageArrived" ascii //weight: 2
        $x_2_3 = "pnservice_BR" ascii //weight: 2
        $x_2_4 = "_apilink" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

