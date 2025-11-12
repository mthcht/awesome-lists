rule Trojan_Win32_NSteal_SB_2147956366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSteal.SB"
        threat_id = "2147956366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-255] 73 00 74 00 61 00 72 00 74 00 [0-48] 2f 00 6d 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 [0-255] 68 00 65 00 6c 00 70 00 65 00 72 00 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSteal_SA_2147957302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSteal.SA"
        threat_id = "2147957302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "\\nodejs\\node.exe" wide //weight: -10
        $n_10_2 = "\\appdata\\local\\programs\\node\\node.exe" wide //weight: -10
        $x_1_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-255] 73 00 74 00 61 00 72 00 74 00 [0-48] 2f 00 6d 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 [0-255] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

