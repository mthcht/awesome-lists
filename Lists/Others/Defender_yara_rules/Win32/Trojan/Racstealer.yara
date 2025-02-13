rule Trojan_Win32_Racstealer_RS_2147899227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racstealer.RS!MTB"
        threat_id = "2147899227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f be 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb}  //weight: 1, accuracy: High
        $x_1_2 = "aspr_keys.ini" ascii //weight: 1
        $x_1_3 = "WmM2MzE3NWozMDIwMzJlPz08Zz0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

