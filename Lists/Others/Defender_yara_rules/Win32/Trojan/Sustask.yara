rule Trojan_Win32_Sustask_B_2147844316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sustask.B"
        threat_id = "2147844316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sustask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-240] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-240] 2f 00 74 00 72 00 [0-240] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 69 00 6e 00 64 00 65 00 78 00 69 00 6e 00 67 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sustask_C_2147844317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sustask.C"
        threat_id = "2147844317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sustask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-240] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-240] 2f 00 74 00 72 00 [0-240] 6d 00 6e 00 6f 00 6c 00 79 00 6b 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

