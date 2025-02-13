rule Trojan_Win32_Stop_RD_2147831857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stop.RD!MTB"
        threat_id = "2147831857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 24 8b 44 24 28 01 44 24 24 8b 4c 24 18 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 74 24 38 8b 44 24 24 31 44 24 10 33 74 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 2c 29 44 24 14 89 7c 24 20 81 6c 24 20 36 dd 96 53 81 44 24 20 3a dd 96 53 8b 44 24 14 8b 4c 24 20 d3 e0 89 7c 24 1c 03 44 24 3c 89 44 24 10 8b 44 24 28 01 44 24 1c 8b 44 24 14 90 01 44 24 1c 8b 44 24 1c 89 44 24 24 8b 44 24 14 8b 4c 24 18 8b d0 d3 ea 8d 4c 24 2c 89 54 24 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

