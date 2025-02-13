rule Trojan_Win32_PassHashDumpAD_A_2147729799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PassHashDumpAD.A"
        threat_id = "2147729799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PassHashDumpAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "find.exe" wide //weight: 1
        $x_1_2 = " /i" wide //weight: 1
        $x_1_3 = "\"cpassword\"" wide //weight: 1
        $x_1_4 = "\\sysvol\\" wide //weight: 1
        $x_1_5 = "\\policies\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PassHashDumpAD_B_2147729800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PassHashDumpAD.B"
        threat_id = "2147729800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PassHashDumpAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 20 00 2f 00 69 00 20 00 22 00 63 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 22 00 20 00 5c 00 5c 00 [0-255] 5c 00 73 00 79 00 73 00 76 00 6f 00 6c 00 5c 00 [0-255] 5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

