rule Trojan_Win32_DiscoveryViaCmd_A_2147920799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiscoveryViaCmd.A"
        threat_id = "2147920799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiscoveryViaCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 00 75 00 65 00 72 00 79 00 20 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 3e 00 [0-2] 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-16] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 70 00 72 00 65 00 73 00 75 00 6c 00 74 00 20 00 2f 00 76 00 20 00 3e 00 20 00 [0-2] 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-32] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_6_3 = ":\\windows\\system32\\cmd.exe /c" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

