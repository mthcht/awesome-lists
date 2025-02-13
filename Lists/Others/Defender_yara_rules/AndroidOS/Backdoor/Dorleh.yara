rule Backdoor_AndroidOS_Dorleh_A_2147829035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Dorleh.A!MTB"
        threat_id = "2147829035"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Dorleh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CSmsSimMessages" ascii //weight: 1
        $x_1_2 = "ContactPhones" ascii //weight: 1
        $x_1_3 = "last_time_contacted" ascii //weight: 1
        $x_1_4 = "//browser/searches" ascii //weight: 1
        $x_1_5 = "getConnectionInfo" ascii //weight: 1
        $x_1_6 = "Lexample/helloandroid/e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

