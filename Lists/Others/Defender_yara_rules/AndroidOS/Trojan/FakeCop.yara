rule Trojan_AndroidOS_FakeCop_B_2147794225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeCop.B"
        threat_id = "2147794225"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeCop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UP_REGISTER_INFO" ascii //weight: 1
        $x_1_2 = ".jobs.WhatService" ascii //weight: 1
        $x_1_3 = "UP_MESSAGE_BRODCAST_INFOG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeCop_2147797801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeCop.h"
        threat_id = "2147797801"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeCop"
        severity = "Critical"
        info = "h: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 4d 53 e6 94 b6 4e 4f 57}  //weight: 1, accuracy: High
        $x_1_2 = "client received...." ascii //weight: 1
        $x_1_3 = "U_SEND_LIST" ascii //weight: 1
        $x_1_4 = "U_SEND_COMPLETED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

