rule Trojan_Win32_DefenderFirewallTamper_A_2147750061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenderFirewallTamper.A"
        threat_id = "2147750061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderFirewallTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Firewall" wide //weight: 1
        $x_1_2 = {2d 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 [0-16] 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 [0-1] 66 00 69 00 6c 00 65 00 73 00 [0-1] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 [0-96] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 61 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 20 00 74 00 68 00 72 00 65 00 61 00 74 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 5c 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 74 00 69 00 6f 00 6e 00 20 00 [0-16] 62 00 6c 00 6f 00 63 00 6b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_DefenderFirewallTamper_B_2147841407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenderFirewallTamper.B"
        threat_id = "2147841407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderFirewallTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Firewall" wide //weight: 10
        $x_1_2 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 [0-96] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-96] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-96] 73 00 65 00 6e 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_10_5 = {61 00 63 00 74 00 69 00 6f 00 6e 00 [0-16] 62 00 6c 00 6f 00 63 00 6b 00}  //weight: 10, accuracy: Low
        $n_100_6 = "SELECT PathName FROM Win32_Service Where Name='bth monitor'" wide //weight: -100
        $n_100_7 = {4d 00 73 00 53 00 65 00 6e 00 73 00 65 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 44 00 69 00 72 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 75 00 74 00 62 00 6f 00 75 00 6e 00 64 00 20 00 2d 00 41 00 63 00 74 00 69 00 6f 00 6e 00 20 00 41 00 6c 00 6c 00 6f 00 77 00}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

