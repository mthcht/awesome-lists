rule Trojan_Win32_Zpevdo_AS_2147789250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zpevdo.AS!MTB"
        threat_id = "2147789250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zpevdo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44}  //weight: 10, accuracy: High
        $x_3_2 = "Rich.pdb" ascii //weight: 3
        $x_3_3 = "Steamthank" ascii //weight: 3
        $x_3_4 = "Usestay" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

