rule Backdoor_MacOS_X_Tsunami_A_2147650894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Tsunami.A"
        threat_id = "2147650894"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Tsunami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TSUNAMI <target> <secs>" ascii //weight: 1
        $x_1_2 = "NOTICE %s :Kaiten wa goraku" ascii //weight: 1
        $x_1_3 = "NICK %s\\nUSER %s localhost localhost :%s" ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686)" ascii //weight: 1
        $x_3_5 = {0f af f1 b9 7b 51 c3 b8 89 f0 f7 e9 89 d0 8d 04 30 89 c1 c1 e9 1f c1 f8 0f 8d 04 08 69 c0 5a b1 00 00}  //weight: 3, accuracy: High
        $x_3_6 = {0f af c8 c7 85 ac fb ff ff 7b 51 c3 b8 8b 85 ac fb ff ff f7 e9 8d 04 0a 89 c2 c1 fa 0f 89 c8 c1 f8 1f 89 d3 29 c3}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

