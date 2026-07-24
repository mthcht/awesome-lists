rule Trojan_Win32_Curlygate_YDQ_2147974387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YDQ!MTB"
        threat_id = "2147974387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 8b 70 08 48 8b 1d fc 0f 01 00 31 c0 f0 48 0f b1 33 40 0f 94 c5 48 39 c6 0f 94 c0 40 08 e8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 04 24 48 8b 00 8b 00 25 ff ff f8 00 3d 48 f7 c0 00 75 38 eb 10 48 8b 04 24 48 8b 08 48 83 c1 07 48 89 08 eb 12 48 8b 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

