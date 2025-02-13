rule Trojan_Win32_CommandlineTaintedTrigger_A_2147765044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CommandlineTaintedTrigger.A"
        threat_id = "2147765044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CommandlineTaintedTrigger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "istaintedmachinea" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CommandlineTaintedTrigger_B_2147765045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CommandlineTaintedTrigger.B"
        threat_id = "2147765045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CommandlineTaintedTrigger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "istaintedmachineb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CommandlineTaintedTrigger_C_2147765838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CommandlineTaintedTrigger.C!low"
        threat_id = "2147765838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CommandlineTaintedTrigger"
        severity = "Critical"
        info = "low: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "istaintedmachineml_low" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CommandlineTaintedTrigger_C_2147765839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CommandlineTaintedTrigger.C!med"
        threat_id = "2147765839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CommandlineTaintedTrigger"
        severity = "Critical"
        info = "med: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "istaintedmachineml_med" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CommandlineTaintedTrigger_C_2147765840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CommandlineTaintedTrigger.C!high"
        threat_id = "2147765840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CommandlineTaintedTrigger"
        severity = "Critical"
        info = "high: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "istaintedmachineml_high" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

