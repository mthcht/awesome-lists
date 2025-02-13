rule Trojan_Win32_HeavensGateShell_YAA_2147901111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HeavensGateShell.YAA!MTB"
        threat_id = "2147901111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HeavensGateShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 20 8b 46 28 31 04 11 83 c2 04 3b 56 24 72 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

