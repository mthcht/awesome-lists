rule Trojan_Win32_RyukLocalspawn_A_2147910469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RyukLocalspawn.A"
        threat_id = "2147910469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RyukLocalspawn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 6d 00 69 00 63 00 2e 00 65 00 78 00 65 00 [0-32] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-32] 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 [0-240] 72 00 75 00 6e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 6d 00 69 00 63 00 [0-32] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-32] 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 [0-240] 72 00 75 00 6e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $n_10_3 = "node:" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

