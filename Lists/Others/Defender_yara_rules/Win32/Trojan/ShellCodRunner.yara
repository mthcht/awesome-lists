rule Trojan_Win32_ShellCodRunner_ZZ_2147942429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodRunner.ZZ!MTB"
        threat_id = "2147942429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 c4 48 89 c5 66 0f ef c0 48 01 be 80 20 00 00 49 c1 fc 15 0f 29 40 10 48 c1 fd 0c 48 89 78 08 48 c7 00 01 00 00 00 41 0f b6 c4 4c 8d 2c c6 49 8b 95 a8 20 00 00 48 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

