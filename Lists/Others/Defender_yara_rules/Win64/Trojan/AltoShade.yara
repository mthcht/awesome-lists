rule Trojan_Win64_AltoShade_A_2147982311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AltoShade.A!dha"
        threat_id = "2147982311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AltoShade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AltosecHVNC_%d" wide //weight: 2
        $x_2_2 = "[Altosec Agent] Starting. Press Ctrl+C or close this window to stop." ascii //weight: 2
        $x_2_3 = "[Altosec Agent] Auth accepted -- streaming. Ready." ascii //weight: 2
        $x_1_4 = "hvnc_agent.log" wide //weight: 1
        $x_1_5 = "--desktop=%d --parent-pid=%u" wide //weight: 1
        $x_1_6 = "[Desktop #%d] %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

