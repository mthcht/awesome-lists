rule Trojan_Win32_SuspMshtaInvoke_ZPA_2147934574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMshtaInvoke.ZPA"
        threat_id = "2147934574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMshtaInvoke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" wide //weight: 1
        $x_1_2 = "javascript:" wide //weight: 1
        $x_1_3 = "GetObject(" wide //weight: 1
        $x_1_4 = "script:" wide //weight: 1
        $x_1_5 = ".Exec()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

