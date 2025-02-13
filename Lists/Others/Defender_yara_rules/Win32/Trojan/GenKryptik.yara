rule Trojan_Win32_GenKryptik_S_2147741120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenKryptik.S!MTB"
        threat_id = "2147741120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenKryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d6 8a 4d ?? 80 e2 ?? 80 e6 ?? c0 e1 ?? 0a 4c 38 ?? c0 e2 ?? 0a 14 38 c0 e6 ?? 0a 74 38}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c7 d3 ea 03 55 c4 33 d0 33 d6 8b 75 d0 2b f2 89 75 d0 c1 e3}  //weight: 1, accuracy: High
        $x_1_3 = "Digiyeyo dogulawoxe hizo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

