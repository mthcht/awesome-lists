rule Trojan_Win32_JScealExec_A_2147969014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealExec.A"
        threat_id = "2147969014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 [0-2] 20 00 2e 00 5c 00 61 00 70 00 70 00 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
        $n_10_2 = "avoid_duplicate-{bcdc7964-2795-4716-a0d4-6d086dbc8872}" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

