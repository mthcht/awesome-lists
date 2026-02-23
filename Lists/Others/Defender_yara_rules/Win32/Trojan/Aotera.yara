rule Trojan_Win32_Aotera_GVG_2147963511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aotera.GVG!MTB"
        threat_id = "2147963511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c1 44 6b 45 a8 0d 41 03 c0 25 ff 0f 00 00 41 3b 47 08 73 44 4c 8b 45 90 45 8b d0 44 33 95 64 ff ff ff 45 88 54 07 10 ff c1 89 4d 8c 48 8b 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

