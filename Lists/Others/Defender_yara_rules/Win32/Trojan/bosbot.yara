rule Trojan_Win32_bosbot_A_2147624766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/bosbot.A"
        threat_id = "2147624766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "bosbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "114"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "Hello, KuGou!" ascii //weight: 100
        $x_10_2 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 2e 6b 65 79 35 31 38 38 2e 63 6f 6d 2f [0-16] 2f [0-16] 2e 61 73 70}  //weight: 10, accuracy: Low
        $x_10_3 = {64 6f 77 6e 75 72 6c 3d 68 74 74 70 3a 2f 2f [0-16] 2e 63 6f 6d 2f 63 6f 75 6e 74 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_10_4 = {64 6f 77 6e 75 72 6c 3d 68 74 74 70 3a 2f 2f [0-16] 2e 63 6e 2f [0-8] 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_1_5 = "DisableWindowsUpdateAccess" ascii //weight: 1
        $x_1_6 = "popurltime=" ascii //weight: 1
        $x_1_7 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = {65 78 65 66 69 6c 65 3d 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_9 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\" ascii //weight: 1
        $x_1_10 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

