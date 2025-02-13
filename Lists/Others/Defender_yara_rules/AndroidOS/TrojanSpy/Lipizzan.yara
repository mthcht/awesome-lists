rule TrojanSpy_AndroidOS_Lipizzan_A_2147816329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Lipizzan.A!MTB"
        threat_id = "2147816329"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Lipizzan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fetchContacts" ascii //weight: 1
        $x_1_2 = "fetchCallLogs" ascii //weight: 1
        $x_1_3 = "fetchSms" ascii //weight: 1
        $x_1_4 = {63 6f 6d 2f [0-24] 66 65 74 63 68 65 72 73 2f 46 65 74 63 68 65 72 73 4d 61 6e 61 67 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = "getEmails" ascii //weight: 1
        $x_1_6 = "dumpDataToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

