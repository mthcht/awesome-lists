rule Trojan_Win32_AllegatoRAT_RD_2147839422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AllegatoRAT.RD!MTB"
        threat_id = "2147839422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AllegatoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8a 14 37 03 c2 99 f7 f9 8a 04 17 88 45 f2 8d 45 e0 8b 55 fc 8b 4d f4 8a 54 0a ff 8a 4d f2 32 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

