rule Trojan_Win32_PromptFilecoder_ZZB_2147951837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PromptFilecoder.ZZB!MTB"
        threat_id = "2147951837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PromptFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "llm-ransom/llm.go" ascii //weight: 1
        $x_1_2 = "main.serverip" ascii //weight: 1
        $x_1_3 = "main.model" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PromptFilecoder_ZZB_2147951837_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PromptFilecoder.ZZB!MTB"
        threat_id = "2147951837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PromptFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 67 65 74 65 6e 76 [0-16] 68 6f 73 74 6e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 67 65 74 65 6e 76 [0-16] 75 73 65 72 70 72 6f 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 67 65 74 65 6e 76 [0-16] 68 6f 6d 65}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6f 2e 70 6f 70 65 6e [0-16] 70 77 64}  //weight: 1, accuracy: Low
        $x_1_5 = "bit32.bxor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

