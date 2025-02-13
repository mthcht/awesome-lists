rule HackTool_AndroidOS_Didat_A_2147783554_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Didat.A!MTB"
        threat_id = "2147783554"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Didat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSBomber" ascii //weight: 1
        $x_1_2 = "SMSBomber$ContactList" ascii //weight: 1
        $x_1_3 = "pickContacts" ascii //weight: 1
        $x_1_4 = "MESSAGE_COUNT" ascii //weight: 1
        $x_1_5 = "textflooder" ascii //weight: 1
        $x_1_6 = "force_close_max" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

