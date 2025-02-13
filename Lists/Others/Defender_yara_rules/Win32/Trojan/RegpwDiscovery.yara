rule Trojan_Win32_RegpwDiscovery_A_2147766604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegpwDiscovery.A"
        threat_id = "2147766604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegpwDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 [0-64] 71 00 75 00 65 00 72 00 79 00 [0-240] 2d 00 66 00 [0-16] 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 2, accuracy: Low
        $x_2_2 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 [0-64] 71 00 75 00 65 00 72 00 79 00 [0-240] 2f 00 66 00 [0-16] 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 2, accuracy: Low
        $x_2_3 = {72 00 65 00 67 00 20 00 [0-64] 71 00 75 00 65 00 72 00 79 00 [0-240] 2d 00 66 00 [0-16] 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 2, accuracy: Low
        $x_2_4 = {72 00 65 00 67 00 20 00 [0-64] 71 00 75 00 65 00 72 00 79 00 [0-240] 2f 00 66 00 [0-16] 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 2, accuracy: Low
        $x_3_5 = "hklm" wide //weight: 3
        $x_3_6 = "hkey_local_machine" wide //weight: 3
        $n_3_7 = "rapid7\\insight agent" wide //weight: -3
        $n_3_8 = "temp\\ctx-" wide //weight: -3
        $n_3_9 = "delete " wide //weight: -3
        $n_3_10 = "passwordexpirywarning" wide //weight: -3
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

