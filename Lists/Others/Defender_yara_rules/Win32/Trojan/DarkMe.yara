rule Trojan_Win32_DarkMe_MBWQ_2147931704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkMe.MBWQ!MTB"
        threat_id = "2147931704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkMe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 3e 14 00 00 f0 30 00 00 ff ff ff 09 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 64 2b 00 11 cc 2c 00 11 dc 28 00 11 24 ed eb 10 2e ed eb}  //weight: 2, accuracy: High
        $x_1_2 = {39 ed eb 10 3a ed eb 10 00 00 f4 01 00 00 c6 40 14 00 00 00 00 00 20 45 00 11 10 3b 28 11 00 14 00 00 08 50 28 11 76 26 00 11 00 50 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

