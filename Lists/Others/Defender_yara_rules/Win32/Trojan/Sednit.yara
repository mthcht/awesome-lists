rule Trojan_Win32_Sednit_A_2147764632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sednit.A!MSR"
        threat_id = "2147764632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sednit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "php.di-dpu-teg/tcetorp/542.87.23.491//:ptth" ascii //weight: 2
        $x_1_2 = "exe.ecivreslqs\\ecivreS\\" ascii //weight: 1
        $x_1_3 = "RT/ \"IUgubeD\\tfosorciM\\swodniW\" NT/ 4 OM/ ETUNIM CS/ etaerC/ sksathcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sednit_LK_2147845870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sednit.LK!MTB"
        threat_id = "2147845870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sednit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 02 32 44 39 ?? 32 ?? ?? 88 04 1f 4f 8b 0e 83 ff ff 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

