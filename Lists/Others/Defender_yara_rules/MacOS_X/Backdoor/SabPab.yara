rule Backdoor_MacOS_X_SabPab_A_2147656115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/SabPab.A"
        threat_id = "2147656115"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "SabPab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Library/LaunchAgents/" ascii //weight: 1
        $x_1_2 = "runatload" ascii //weight: 1
        $x_2_3 = "SendEventToSystemEventsWithParameters" ascii //weight: 2
        $x_2_4 = "Safari/419.3" ascii //weight: 2
        $x_2_5 = "%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 2
        $x_6_6 = {f7 e9 d1 fa 89 c8 c1 f8 1f}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

