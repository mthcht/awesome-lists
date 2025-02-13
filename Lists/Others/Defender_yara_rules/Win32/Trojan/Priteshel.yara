rule Trojan_Win32_Priteshel_A_2147783751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Priteshel.A"
        threat_id = "2147783751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Priteshel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "New-Object" wide //weight: 1
        $x_1_3 = "Net.Webclient" wide //weight: 1
        $x_1_4 = ".downloadstring" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Priteshel_B_2147783752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Priteshel.B"
        threat_id = "2147783752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Priteshel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-enc" wide //weight: 2
        $x_1_3 = "bypass" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Priteshel_C_2147783957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Priteshel.C"
        threat_id = "2147783957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Priteshel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe /c" wide //weight: 1
        $x_1_2 = "cmd /c" wide //weight: 1
        $x_3_3 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 [0-10] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 3, accuracy: Low
        $x_3_4 = {5c 00 5c 00 5c 00 22 00 74 00 2e 00 [0-10] 2e 00 63 00 6f 00 6d 00 5c 00 5c 00 5c 00}  //weight: 3, accuracy: Low
        $x_3_5 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-16] 2f 00 69 00 [0-16] 68 00 74 00 74 00 70 00 3a 00}  //weight: 3, accuracy: Low
        $x_3_6 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-48] 67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-224] 68 00 74 00 74 00 70 00}  //weight: 3, accuracy: Low
        $n_10_7 = "/c \"start https:" wide //weight: -10
        $n_10_8 = "HybridMailDriver" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

