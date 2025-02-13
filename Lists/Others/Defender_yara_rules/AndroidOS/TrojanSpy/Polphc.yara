rule TrojanSpy_AndroidOS_Polphc_B_2147776254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Polphc.B!MTB"
        threat_id = "2147776254"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Polphc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PreventUninstall" ascii //weight: 1
        $x_1_2 = "DisablePlayProtect" ascii //weight: 1
        $x_1_3 = "SmsAutoAccept" ascii //weight: 1
        $x_1_4 = "GetSmsUpload" ascii //weight: 1
        $x_1_5 = "GetInjectsServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

