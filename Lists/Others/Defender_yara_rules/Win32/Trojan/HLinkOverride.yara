rule Trojan_Win32_HLinkOverride_A_2147760204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HLinkOverride.A!winbio"
        threat_id = "2147760204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HLinkOverride"
        severity = "Critical"
        info = "winbio: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-80] 6d 00 6b 00 6c 00 69 00 6e 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 [0-80] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 62 00 69 00 6f 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HLinkOverride_C_2147773456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HLinkOverride.C!gen"
        threat_id = "2147773456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HLinkOverride"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-80] 6d 00 6b 00 6c 00 69 00 6e 00 6b 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 [0-80] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-80] 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 [0-80] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-80] 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 [0-80] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 69 00 6e 00 73 00 78 00 73 00 5c 00 [0-80] 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 [0-80] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 69 00 6e 00 73 00 78 00 73 00 5c 00 [0-80] 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $n_10_6 = "os.2020" wide //weight: -10
        $n_10_7 = "onecore" wide //weight: -10
        $n_10_8 = "amcore" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

