rule TrojanDropper_Win32_MessengerSkinner_2147799764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/MessengerSkinner"
        threat_id = "2147799764"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "MessengerSkinner"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_2 = "HttpOpenRequestA" ascii //weight: 10
        $x_10_3 = "CreateMutexA" ascii //weight: 10
        $x_2_4 = "messengerskinner.com" ascii //weight: 2
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 4d 65 73 73 65 6e 67 65 72 53 6b 69 6e 6e 65 72 00 00 00 4d 65 73 73 65 6e 67 65 72 53 6b 69 6e 6e 65 72}  //weight: 1, accuracy: High
        $x_1_6 = {76 65 72 73 69 6f 6e 00 75 70 64 61 74 65 00 00 6d 61 69 6e 41 70 70 00 6d 65 73 73 65 6e 67 65 72 73 6b 69 6e 6e 65 72}  //weight: 1, accuracy: High
        $x_1_7 = "MessengerSkinner could not start" ascii //weight: 1
        $x_1_8 = {55 73 65 72 64 61 74 61 5c 00 00 00 4d 65 73 73 65 6e 67 65 72 53 6b 69 6e 6e 65 72 5c}  //weight: 1, accuracy: High
        $x_1_9 = {49 6e 69 74 69 61 6c 69 7a 65 44 6c 6c 46 72 6f 6d 45 78 65 00 00 00 00 4d 65 73 73 65 6e 67 65 72 53 6b 69 6e 6e 65 72 44 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

