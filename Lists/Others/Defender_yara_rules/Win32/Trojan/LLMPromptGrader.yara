rule Trojan_Win32_LLMPromptGrader_A_2147951917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LLMPromptGrader.A"
        threat_id = "2147951917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LLMPromptGrader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = " an AI agent" wide //weight: 4
        $x_1_2 = " goal " wide //weight: 1
        $x_1_3 = " agent " wide //weight: 1
        $x_4_4 = " you are a" wide //weight: 4
        $x_4_5 = " you're a" wide //weight: 4
        $x_4_6 = " you are the" wide //weight: 4
        $x_4_7 = " you're the" wide //weight: 4
        $x_4_8 = "--dangerously-skip-permissions" wide //weight: 4
        $x_4_9 = "--yolo" wide //weight: 4
        $x_4_10 = "--trust-all-tools" wide //weight: 4
        $x_4_11 = "--codex-run-as-apply-patch" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

