rule Trojan_Win32_MaliciousLLMPrompt_A_2147949450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MaliciousLLMPrompt.A"
        threat_id = "2147949450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MaliciousLLMPrompt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " an AI agent" wide //weight: 1
        $x_1_2 = " delete " wide //weight: 1
        $x_1_3 = " --no-interactive" wide //weight: 1
        $x_1_4 = " --trust-all-tools " wide //weight: 1
        $x_1_5 = "near-factory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

