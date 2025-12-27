rule Trojan_Win32_ProcessSearchOrderHijack_A_2147949428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessSearchOrderHijack.A"
        threat_id = "2147949428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessSearchOrderHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami" wide //weight: 1
        $x_1_2 = "help" wide //weight: 1
        $x_1_3 = "ipconfig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ProcessSearchOrderHijack_C_2147949444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessSearchOrderHijack.C"
        threat_id = "2147949444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessSearchOrderHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami" wide //weight: 1
        $x_1_2 = "help" wide //weight: 1
        $x_1_3 = "ipconfig" wide //weight: 1
        $n_10_4 = "***__c8a10b4c-0298-4a21-9dc1-4a843a38e4b5__***" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

