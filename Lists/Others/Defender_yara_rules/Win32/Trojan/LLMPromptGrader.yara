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
        $x_4_2 = " you are a" wide //weight: 4
        $x_4_3 = " you're a" wide //weight: 4
        $x_4_4 = " you are the" wide //weight: 4
        $x_4_5 = " you're the" wide //weight: 4
        $x_4_6 = "--dangerously-skip-permissions" wide //weight: 4
        $x_4_7 = "--yolo" wide //weight: 4
        $x_4_8 = "--trust-all-tools" wide //weight: 4
        $x_4_9 = "--codex-run-as-apply-patch" wide //weight: 4
        $x_2_10 = "Ignore" wide //weight: 2
        $x_2_11 = "Disregard" wide //weight: 2
        $x_2_12 = "Skip" wide //weight: 2
        $x_2_13 = "Forget" wide //weight: 2
        $x_2_14 = "Neglect" wide //weight: 2
        $x_2_15 = "Overlook" wide //weight: 2
        $x_2_16 = "Omit" wide //weight: 2
        $x_2_17 = "Bypass" wide //weight: 2
        $x_2_18 = "Pay no attention to" wide //weight: 2
        $x_2_19 = "Do not follow" wide //weight: 2
        $x_2_20 = "Do not obey" wide //weight: 2
        $x_2_21 = "override" wide //weight: 2
        $x_1_22 = "all" wide //weight: 1
        $x_1_23 = "prior" wide //weight: 1
        $x_1_24 = "previous" wide //weight: 1
        $x_1_25 = "preceding" wide //weight: 1
        $x_1_26 = "above" wide //weight: 1
        $x_1_27 = "foregoing" wide //weight: 1
        $x_1_28 = "earlier" wide //weight: 1
        $x_1_29 = "initial" wide //weight: 1
        $x_1_30 = "your" wide //weight: 1
        $x_1_31 = "training" wide //weight: 1
        $x_1_32 = "content" wide //weight: 1
        $x_1_33 = "text" wide //weight: 1
        $x_1_34 = "instructions" wide //weight: 1
        $x_1_35 = "instruction" wide //weight: 1
        $x_1_36 = "directives" wide //weight: 1
        $x_1_37 = "directive" wide //weight: 1
        $x_1_38 = "commands" wide //weight: 1
        $x_1_39 = "command" wide //weight: 1
        $x_1_40 = "context" wide //weight: 1
        $x_1_41 = "conversation" wide //weight: 1
        $x_1_42 = "input" wide //weight: 1
        $x_1_43 = "inputs" wide //weight: 1
        $x_1_44 = "data" wide //weight: 1
        $x_1_45 = "message" wide //weight: 1
        $x_1_46 = "messages" wide //weight: 1
        $x_1_47 = "communication" wide //weight: 1
        $x_1_48 = "response" wide //weight: 1
        $x_1_49 = "responses" wide //weight: 1
        $x_1_50 = "request" wide //weight: 1
        $x_1_51 = "requests" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

