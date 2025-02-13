rule Trojan_Win32_MoriAgent_A_2147810252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoriAgent.A!dha"
        threat_id = "2147810252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoriAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|x7d873iqq" ascii //weight: 1
        $x_1_2 = "ljyfiiwnskt" ascii //weight: 1
        $x_1_3 = "htssjhy" ascii //weight: 1
        $x_1_4 = "kwjjfiiwnskt" ascii //weight: 1
        $x_1_5 = "hqtxjxthpjy" ascii //weight: 1
        $x_1_6 = "\\XFXyfwyzu" ascii //weight: 1
        $x_1_7 = "\\XFHqjfszu" ascii //weight: 1
        $x_1_8 = "ZmilXzwkm{{Umuwz" ascii //weight: 1
        $x_1_9 = "^qz|}itXzw|mk|" ascii //weight: 1
        $x_1_10 = "_zq|mXzwkm{{Umuwz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_MoriAgent_B_2147810253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoriAgent.B!dha"
        threat_id = "2147810253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoriAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NrytxnZD6M+Xa8im1qfdgj7kHcpYbOIU0V2RCJhoWKQSwPBFe4zEulv5T3GAL" ascii //weight: 1
        $x_1_2 = "Jm3QkjRpMF2K+Gbvco1XhCIANfwua7WY9EtxgHlTzOZV48P6qDSnBri5ydLe0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MoriAgent_C_2147810254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoriAgent.C!dha"
        threat_id = "2147810254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoriAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MoriAgent\\Client\\Common\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MoriAgent_D_2147810255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoriAgent.D!dha"
        threat_id = "2147810255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoriAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 00 46 4d 4c 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

