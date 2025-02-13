rule Trojan_Win32_Eson_C_2147614562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eson.C"
        threat_id = "2147614562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 65 72 76 69 63 65 73 00 65 64 72 74 68 65}  //weight: 10, accuracy: High
        $x_2_2 = "sdf7sd7fa7dfaf4" wide //weight: 2
        $x_2_3 = "v2\\Pagina\\Proyecto1.vbp" wide //weight: 2
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_5 = {00 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Eson_D_2147614563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eson.D"
        threat_id = "2147614563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {77 69 6e 6c 6f 67 6f 6e 00 73 64 61 66 73}  //weight: 10, accuracy: High
        $x_2_2 = "rgsgsegsegs" wide //weight: 2
        $x_2_3 = "Bomba logica\\Proyecto1.vbp" wide //weight: 2
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_5 = {00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 52 00 75 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

