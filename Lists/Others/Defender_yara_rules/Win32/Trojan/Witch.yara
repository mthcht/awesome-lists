rule Trojan_Win32_Witch_BH_2147828040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Witch.BH!MTB"
        threat_id = "2147828040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Witch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 f4 03 55 08 0f b6 02 33 c1 8b 4d f4 03 4d 08 88 01 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

