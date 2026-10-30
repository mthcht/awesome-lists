rule Trojan_Win32_SuspCurlExec_A_2147980461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCurlExec.A"
        threat_id = "2147980461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCurlExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = {20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 28 07 07 00 29 03 03 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = "msiexec" wide //weight: 1
        $x_1_5 = ".msi" wide //weight: 1
        $x_1_6 = " && " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspCurlExec_B_2147981257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCurlExec.B"
        threat_id = "2147981257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCurlExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = {20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 28 07 07 00 29 03 03 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = " && powershell" wide //weight: 1
        $x_1_5 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

