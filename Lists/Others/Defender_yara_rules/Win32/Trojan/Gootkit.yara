rule Trojan_Win32_Gootkit_KA_2147743239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gootkit.KA!MSR"
        threat_id = "2147743239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gootkit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "crackmeololo" ascii //weight: 2
        $x_1_2 = "--vwxyz" ascii //weight: 1
        $x_1_3 = "RunPreSetupCommands" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gootkit_DSK_2147755479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gootkit.DSK!MTB"
        threat_id = "2147755479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 fc 81 ea d0 07 00 00 89 55 fc c1 4d 08 09 8b 45 fc 2d 00 10 00 00 89 45 fc 8b 4d 08 33 4d 0c 89 4d 08 8b 55 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

