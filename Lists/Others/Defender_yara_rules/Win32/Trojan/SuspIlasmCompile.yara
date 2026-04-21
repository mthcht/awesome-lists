rule Trojan_Win32_SuspIlasmCompile_A_2147967372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspIlasmCompile.A"
        threat_id = "2147967372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspIlasmCompile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ilasm" wide //weight: 1
        $x_1_2 = ".il" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

