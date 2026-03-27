rule Trojan_Win32_BuhTrap_MK_2147965736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BuhTrap.MK!MTB"
        threat_id = "2147965736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BuhTrap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {0f 10 44 02 c0 66 0f fc c1 0f 11 40 c0 0f 10 44 07 c0 66 0f fc c1 0f 11 40 d0 0f 10 44 03 c0 66 0f fc c1 0f 11 40 e0 0f 10 44 06 c0 66 0f fc c1 0f 11 40 f0 83 e9 01}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

