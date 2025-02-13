rule Backdoor_Win32_LittleWitch_AA_2147792376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/LittleWitch.AA"
        threat_id = "2147792376"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "LittleWitch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "155"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {05 00 00 00 52 65 67 69 73 00 00 00 ff ff ff ff 03 00 00 00 74 65 72 00 ff ff ff ff 07 00 00 00 53 65 72 76 69 63 65 00 ff ff ff ff 07 00 00 00 50 72 6f 63 65 73 73 00}  //weight: 50, accuracy: High
        $x_50_2 = {0e 00 00 00 65 63 68 6f 20 73 7c 66 6f 72 6d 61 74 20 00 00 ff ff ff ff 04 00 00 00 3a 20 2f 51}  //weight: 50, accuracy: High
        $x_50_3 = {05 00 00 00 2a 2e 75 69 6e 00 00 00 ff ff ff ff 03 00 00 00 63 3a 5c 00}  //weight: 50, accuracy: High
        $x_1_4 = "ExploreWClass" ascii //weight: 1
        $x_1_5 = {4d 53 4e 00}  //weight: 1, accuracy: High
        $x_1_6 = "VERLWSERVER6" ascii //weight: 1
        $x_1_7 = "PASSWORDCAHYNA" ascii //weight: 1
        $x_1_8 = "littlewitch" ascii //weight: 1
        $x_1_9 = "Nickname" ascii //weight: 1
        $x_1_10 = "WARNING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

