rule Trojan_AndroidOS_BankerBel_A_2147829275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerBel.A"
        threat_id = "2147829275"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerBel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gamble_url" ascii //weight: 2
        $x_2_2 = "WhatScan2022_" ascii //weight: 2
        $x_2_3 = "start_work_me: thread: knocking..." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

