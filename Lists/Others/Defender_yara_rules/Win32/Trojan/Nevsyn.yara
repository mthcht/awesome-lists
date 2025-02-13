rule Trojan_Win32_Nevsyn_A_2147654885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nevsyn.A"
        threat_id = "2147654885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nevsyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 50 01 8a 08 40 84 c9 75 f9 2b c2 33 c9 85 c0 7e 11 80 3e 2e 75 01 47 83 ff 02 74 06}  //weight: 2, accuracy: High
        $x_1_2 = "DDOS\\SynDDos\\bin\\Release\\UUSynServer" ascii //weight: 1
        $x_1_3 = {50 72 6f 64 75 63 74 4e 61 6d 65 00 32 30 30 30}  //weight: 1, accuracy: High
        $x_1_4 = {5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 00 00 7e 4d 48 7a}  //weight: 1, accuracy: High
        $x_1_5 = "synserver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

