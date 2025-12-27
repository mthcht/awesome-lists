rule Trojan_Win32_Sysdupate_GVA_2147955711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sysdupate.GVA!MTB"
        threat_id = "2147955711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sysdupate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 7d f4 68 04 01 00 00 8d 85 f0 fe ff ff 50 a5 66 a5 a4 33 f6 56}  //weight: 1, accuracy: High
        $x_2_2 = {8b f8 0f b7 06 8b cf c1 c9 08 46 03 c8 33 f9 80 3e 00 75 ee}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

