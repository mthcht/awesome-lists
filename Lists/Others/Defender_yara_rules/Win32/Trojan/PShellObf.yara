rule Trojan_Win32_PShellObf_SA_2147937802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellObf.SA"
        threat_id = "2147937802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellObf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = {5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 31 00 30 00 35 00 29 00 [0-16] 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 31 00 30 00 31 00 29 00 [0-16] 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 31 00 32 00 30 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PShellObf_SAB_2147940948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellObf.SAB"
        threat_id = "2147940948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellObf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = {5b 00 63 00 68 00 61 00 72 00 5d 00 [0-2] 31 00 30 00 35 00 [0-16] 5b 00 63 00 68 00 61 00 72 00 5d 00 [0-2] 31 00 30 00 31 00 [0-16] 5b 00 63 00 68 00 61 00 72 00 5d 00 [0-2] 31 00 32 00 30 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 63 00 68 00 61 00 72 00 5d 00 [0-2] 31 00 30 00 35 00 [0-16] 5b 00 63 00 68 00 61 00 72 00 5d 00 [0-2] 31 00 31 00 39 00 [0-16] 5b 00 63 00 68 00 61 00 72 00 5d 00 [0-2] 31 00 31 00 34 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

