rule Trojan_Win32_Balisdat_A_2147617716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Balisdat.gen!A"
        threat_id = "2147617716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Balisdat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 5c [0-37] 6e 75 52}  //weight: 1, accuracy: Low
        $x_1_2 = {73 65 69 74 69 63 6f 65 67 [0-6] 2f 2f 3a 70 74 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = "land\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Balisdat_B_2147648439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Balisdat.gen!B"
        threat_id = "2147648439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Balisdat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 66 7a 66 2e [0-16] 5c 3a 64}  //weight: 1, accuracy: Low
        $x_1_2 = "ovS\\opjtsfXuofssvD" ascii //weight: 1
        $x_1_3 = "//:quui" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Balisdat_D_2147652791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Balisdat.gen!D"
        threat_id = "2147652791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Balisdat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "TmrUACTimer" ascii //weight: 2
        $x_1_2 = {8d 45 d4 e8 ?? ?? ?? ?? ff 75 d4 68 ?? ?? ?? ?? 8d 55 d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 d0 b8 ?? ?? ?? ?? ba 04 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 cc e8 ?? ?? ?? ?? ff 75 cc}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 00 6a 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 00 01 00 00 00 a1 ?? ?? ?? ?? 8b 00 8b 80 ?? 03 00 00 b2 01 e8 ?? ?? ?? ?? eb 1f a1 ?? ?? ?? ?? c7 00 02 00 00 00 a1 ?? ?? ?? ?? 8b 00 8b 80 03 03 00 00 b2 01 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Balisdat_D_2147653912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Balisdat.D"
        threat_id = "2147653912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Balisdat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fzf.eqvoja\\tsfxjse\\:D" ascii //weight: 1
        $x_1_2 = "fzf.otn\\tsfxjse\\:D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

