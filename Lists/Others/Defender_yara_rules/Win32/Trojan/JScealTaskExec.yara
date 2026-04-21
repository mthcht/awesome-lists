rule Trojan_Win32_JScealTaskExec_A_2147965391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.A"
        threat_id = "2147965391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " -enc" wide //weight: 1
        $x_1_3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBv" wide //weight: 1
        $x_1_4 = "AG4AUABhAHQAaAAgACgARwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AKQAgAC0ARgBvAHIAYwBlAA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_JScealTaskExec_B_2147965392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.B"
        threat_id = "2147965392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " -enc" wide //weight: 1
        $x_1_3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUAByAG8AYwBlAHMAcwAgACgARwBlAHQALQBQAH" wide //weight: 1
        $x_1_4 = "IAbwBjAGUAcwBzACAALQBQAEkARAAgACQAUABJAEQAKQAuAE0AYQBpAG4ATQBvAGQAdQBsAGUALgBNAG8AZAB1AGwAZQBOAGEAbQBlACAALQBGAG8AcgBjAGUA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_JScealTaskExec_C_2147965393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.C"
        threat_id = "2147965393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = " -enc" wide //weight: 10
        $x_10_3 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAg" wide //weight: 10
        $x_1_4 = "IAB8ACAASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==" wide //weight: 1
        $x_1_5 = "AHwAIABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4A" wide //weight: 1
        $x_1_6 = "fAAgAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgA=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_JScealTaskExec_AA_2147967451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.AA"
        threat_id = "2147967451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " -e" wide //weight: 1
        $x_1_3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBv" wide //weight: 1
        $x_1_4 = "AG4AUABhAHQAaAAgACgARwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AKQAgAC0ARgBvAHIAYwBlAA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_JScealTaskExec_AB_2147967452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.AB"
        threat_id = "2147967452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " -e" wide //weight: 1
        $x_1_3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUAByAG8AYwBlAHMAcwAgACgARwBlAHQALQBQAH" wide //weight: 1
        $x_1_4 = "IAbwBjAGUAcwBzACAALQBQAEkARAAgACQAUABJAEQAKQAuAE0AYQBpAG4ATQBvAGQAdQBsAGUALgBNAG8AZAB1AGwAZQBOAGEAbQBlACAALQBGAG8AcgBjAGUA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_JScealTaskExec_AC_2147967453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.AC"
        threat_id = "2147967453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = " -e" wide //weight: 10
        $x_10_3 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAg" wide //weight: 10
        $x_1_4 = "IAB8ACAASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==" wide //weight: 1
        $x_1_5 = "AHwAIABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4A" wide //weight: 1
        $x_1_6 = "fAAgAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgA=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

