rule Trojan_Win32_Phorplex_A_2147730614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorplex.A!MTB"
        threat_id = "2147730614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorplex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6b 58 6a 65 5a 6a 72 a2 ?? ?? ?? ?? 58 6a 6e a2 ?? ?? ?? ?? 58 6a 6c a2 ?? ?? ?? ?? 58 6a 33 59 6a 32 88 0d ?? ?? ?? ?? 59 6a 2e 88 0d ?? ?? ?? ?? 59 6a 64 88 0d ?? ?? ?? ?? 59 6a 6b 5f 6a 72 66 89 3d ?? ?? ?? ?? 5f 6a 6e 66 89 3d ?? ?? ?? ?? 5f 6a 33 88 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 66 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4c 2a 03 8a d9 8a c1 80 e1 f0 c0 e0 06 0a 44 2a 02 80 e3 fc c0 e1 02 0a 0c 2a c0 e3 04 0a 5c 2a 01 83 c5 04 88 0c 3e 88 5c 3e 01 88 44 3e 02 83 c6 03 3b 6c 24 14 72 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

