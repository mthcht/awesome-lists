rule Backdoor_MacOS_NimDoor_A_2147946728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/NimDoor.A!MTB"
        threat_id = "2147946728"
        type = "Backdoor"
        platform = "MacOS: "
        family = "NimDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 fe 48 c1 ee 03 83 e6 38 48 8b 44 30 10 48 0f a3 f8 73 0c 48 8b 02 83 e0 01 48 09 c8 48 89 02}  //weight: 1, accuracy: High
        $x_1_2 = {4d 89 77 08 4c 89 e3 48 c1 fb 0c 4c 89 e7 48 c1 ff 15 e8 f8 f5 ff ff 48 89 da 48 c1 ea 03 be 01 00 00 00 89 d9 48 d3 e6 83 e2 38 48 09 74 10 10 4b 8b 54 37 08 31 c9 81 fa 00 01 00 00 0f 93 c1 48 c1 e1 03 31 c0 81 fa 00 00 00 01 0f 93 c0 81 fa 00 00 01 00 48 8d 04 c5 10 00 00 00 48 0f 42 c1 89 d6 89 c1 48 d3 ee}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 f2 48 c1 ea 03 83 e2 38 48 8b 44 10 10 48 0f a3 f0 73 15 49 39 4c 24 08 75 0e 49 8b 07 83 e0 01 48 09 c8 49 89 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

