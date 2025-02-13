rule Trojan_Win32_Netemag_A_2147689353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netemag.A"
        threat_id = "2147689353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netemag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {52 55 46 00 2e 39 33 36 90 01 04 2e 64 61 74}  //weight: 5, accuracy: High
        $x_5_2 = "{DE065B2B-7B54-429b-B071-731355AA6294}" ascii //weight: 5
        $x_5_3 = "WWW.GAME9918.NET" ascii //weight: 5
        $x_10_4 = {6a 08 59 33 c0 c6 45 fc 04 8d 7d 98 f3 ab 8d 85 24 ff ff ff 50 8d 4d b8 e8}  //weight: 10, accuracy: High
        $x_1_5 = "210.14.66.118" ascii //weight: 1
        $x_1_6 = "222.73.104.145" ascii //weight: 1
        $x_1_7 = "210.14.67.102" ascii //weight: 1
        $x_1_8 = "60.29.232.50" ascii //weight: 1
        $x_1_9 = "60.190.218.155" ascii //weight: 1
        $x_1_10 = "61.129.67.238" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

