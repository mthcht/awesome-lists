rule Trojan_Win32_Dostilbot_Z_2147954297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dostilbot.Z!MTB"
        threat_id = "2147954297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dostilbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 cb 0b 41 21 c5 49 83 c2 04 c1 e1 18 c1 e2 10 09 d1 41 0f b6 52 ff 09 d1 41 0f b6 52 fe c1 e2 08 09 d1 89 f2 c1 ca 06 41 89 4a 6c 31 da 89 f3 c1 c3 07 31 da 89 f3 f7 d3 44 21 c3 44 31 eb 01 da 03 57 fc 44 89 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

