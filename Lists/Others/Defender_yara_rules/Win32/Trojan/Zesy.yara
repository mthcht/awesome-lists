rule Trojan_Win32_Zesy_RDA_2147842397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zesy.RDA!MTB"
        threat_id = "2147842397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zesy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c8 8b 08 c1 e9 08 89 4d b4 8b 4d cc 33 4d b4 8b 45 d4 33 d2 f7 75 ac 8b 45 08 03 0c 90 89 4d cc 8b 0d ?? ?? ?? ?? 33 d2 89 4d 80 89 55 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

