rule Trojan_Win32_SusRunDll_MK_2147945829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRunDll.MK"
        threat_id = "2147945829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRunDll"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32" wide //weight: 1
        $x_1_2 = "phonehome" wide //weight: 1
        $x_1_3 = "phonehome_main" wide //weight: 1
        $n_1_4 = "aa06e39e-7876-4ba3-beee-42bd80ff362e" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRunDll_MK_2147945829_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRunDll.MK"
        threat_id = "2147945829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRunDll"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32" wide //weight: 1
        $x_1_2 = "phonehome" wide //weight: 1
        $x_1_3 = "phonehome_main" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

