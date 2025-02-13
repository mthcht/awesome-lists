rule Trojan_Win32_Magania_DSK_2147743921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Magania.DSK!MTB"
        threat_id = "2147743921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Magania"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 1e 01 8a 14 39 46 32 c2 2c 03 bd 06 00 00 00 88 04 39 8b c1 99 f7 fd 85 d2 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

