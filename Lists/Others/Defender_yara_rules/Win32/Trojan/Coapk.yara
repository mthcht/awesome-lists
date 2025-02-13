rule Trojan_Win32_Coapk_ASG_2147894620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coapk.ASG!MTB"
        threat_id = "2147894620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coapk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 ce 21 c9 e8 [0-4] 81 e9 76 81 73 c2 31 02 21 f6 29 ce 42 46 89 c9 39 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {09 d8 81 eb 5f 55 46 1b 31 0e 83 ec 04 c7 04 24 78 e9 02 6d 5b 46 81 c3 01 00 00 00 39 d6 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

