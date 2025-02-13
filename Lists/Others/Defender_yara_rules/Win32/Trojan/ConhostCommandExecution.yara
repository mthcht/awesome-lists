rule Trojan_Win32_ConhostCommandExecution_B_2147768908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ConhostCommandExecution.B"
        threat_id = "2147768908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ConhostCommandExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $n_10_2 = {66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 [0-16] 46 00 6f 00 72 00 63 00 65 00 56 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

