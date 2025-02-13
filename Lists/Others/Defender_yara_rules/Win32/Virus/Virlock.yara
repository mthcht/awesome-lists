rule Virus_Win32_Virlock_PAGC_2147931022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virlock.PAGC!MTB"
        threat_id = "2147931022"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 06 32 c2 90 88 07 42 46 90 47 49 e9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virlock_PAGD_2147931023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virlock.PAGD!MTB"
        threat_id = "2147931023"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c4 c0 03 00 00 c3 e9 ?? ?? ?? ?? 88 07 42 ?? 46 ?? 47 ?? 49 83 f9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b f8 8b df ?? b9 c0 03 00 00 e9 ?? ?? ?? ?? ba 30 00 00 00 8a 06 ?? 32 c2 ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

