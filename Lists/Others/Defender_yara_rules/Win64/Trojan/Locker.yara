rule Trojan_Win64_Locker_KK_2147978331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Locker.KK!MTB"
        threat_id = "2147978331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Locker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 6
        $x_5_2 = "HOW_TO_DECRYPT.txt" ascii //weight: 5
        $x_4_3 = ".locked" ascii //weight: 4
        $x_3_4 = "steal_passwords" ascii //weight: 3
        $x_2_5 = "steal_tokens" ascii //weight: 2
        $x_1_6 = "screen_h264_start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

