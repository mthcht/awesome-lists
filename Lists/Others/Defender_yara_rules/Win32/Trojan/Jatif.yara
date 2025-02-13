rule Trojan_Win32_Jatif_GPN_2147889152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jatif.GPN!MTB"
        threat_id = "2147889152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jatif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f b6 07 0f b6 0e 8b 95 f4 fe ff ff 03 c8 0f b6 c1 8b 8d f0 fe ff ff 8a 84 05 fc fe ff ff 32 04 0a 88 01 41}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

