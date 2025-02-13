rule Trojan_AndroidOS_Adobot_A_2147752537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Adobot.A!MTB"
        threat_id = "2147752537"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Adobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetContactsTask" ascii //weight: 2
        $x_1_2 = "Running GetSmsTask" ascii //weight: 1
        $x_1_3 = "Open adobot" ascii //weight: 1
        $x_1_4 = "appmessages.herokuapp.com" ascii //weight: 1
        $x_1_5 = "content://call_log/calls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

