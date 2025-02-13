rule Backdoor_AndroidOS_Cajino_A_2147782152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Cajino.A!MTB"
        threat_id = "2147782152"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Cajino"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createContactFile" ascii //weight: 1
        $x_1_2 = "deletTempFile" ascii //weight: 1
        $x_1_3 = "call_log" ascii //weight: 1
        $x_1_4 = "upload_message" ascii //weight: 1
        $x_1_5 = "FileDownloadingInfo" ascii //weight: 1
        $x_1_6 = "EXTRA_EXTRA =" ascii //weight: 1
        $x_1_7 = ">>> Receive intent:" ascii //weight: 1
        $x_3_8 = "ca/ji/no" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

