rule Backdoor_Win32_Avrkill_2147607947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Avrkill"
        threat_id = "2147607947"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Avrkill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "104"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {54 61 73 6b 6b 69 6c 6c 20 20 20 2f 66 69 20 20 20 22 69 6d 61 67 65 6e 61 6d 65 20 20 20 65 71 20 20 20 52 41 56 4d 4f 4e 2e 45 58 45 22 20 20 20 2f 66 00 54 61 73 6b 6b 69 6c 6c 20 20 20 2f 66 69 20 20 20 22 69 6d 61 67 65 6e 61 6d 65 20 20 20 65 71 20 20 20 72 66 77 73 72 76 2e 65 78 65 22 20 20 20 2f 66}  //weight: 100, accuracy: High
        $x_1_2 = {57 49 4e 4e 54 00 00 00 63 3a 5c 00 5c 73 65 72 76 65 72 2e 65 78 65 00 73 65 74 73 6f 63 6b 6f 70 74 20 45 72 72 6f 72 21}  //weight: 1, accuracy: High
        $x_1_3 = {44 4f 57 4e 4c 4f 41 44 3a 00 00 00 53 54 4f 50 41 54 54 41 43 4b 00 00 75 64 70}  //weight: 1, accuracy: High
        $x_1_4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_5 = {57 69 6e 45 78 65 63 00 00 00 00 00 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 65 72 76 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "Wireless Zero Configuraction" ascii //weight: 1
        $x_1_7 = "202.104.236.66" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

