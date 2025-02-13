rule Trojan_Linux_SideWalk_A_2147841274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SideWalk.A!MTB"
        threat_id = "2147841274"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SideWalk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W9gNRmdFjxwKQosBYhkYbukO2ejZev4m" ascii //weight: 1
        $x_1_2 = "oRfT6W6ADzQ5G8jidUsfYAWSOIuIKRwc" ascii //weight: 1
        $x_1_3 = "SC_INFO_RECEIVE_MODULE_START_COMMAND" ascii //weight: 1
        $x_1_4 = "SC_INFO_BIZ_MESSAGE_SEND_THREAD_BEGIN" ascii //weight: 1
        $x_1_5 = {0c 20 1b e5 08 30 9b e5 03 00 52 e1 18 00 00 aa 0c 30 1b e5 9c 20 1b e5 03 30 82 e0 00 10 d3 e5 0c 20 1b e5 08 30 1b e5 03 30 42 e0 04 20 4b e2 03 30 82 e0 88 20 53 e5 0c 30 1b e5 04 00 9b e5 03 30 80 e0 01 20 22 e0 ff 20 02 e2 00 20 c3 e5 0c 30 1b e5 01 30 83 e2 0c 30 0b e5 08 30 1b e5 3f 30 83 e2 0c 20 1b e5 03 00 52 e1 e3 ff ff da}  //weight: 1, accuracy: High
        $x_1_6 = "SC_INFO_NETWORK_REVERSE_THREAD_BEGIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

