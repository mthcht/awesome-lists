rule Trojan_Win32_MpTamperASRRule_PSD_2147772287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperASRRule.PSD"
        threat_id = "2147772287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperASRRule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 1
        $x_1_2 = "-mppreference " wide //weight: 1
        $x_1_3 = {2d 00 61 00 74 00 74 00 61 00 63 00 6b 00 73 00 75 00 72 00 66 00 61 00 63 00 65 00 72 00 65 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 72 00 75 00 6c 00 65 00 73 00 5f 00 69 00 64 00 73 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 00 61 00 74 00 74 00 61 00 63 00 6b 00 73 00 75 00 72 00 66 00 61 00 63 00 65 00 72 00 65 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 72 00 75 00 6c 00 65 00 73 00 5f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 73 00 20 00 [0-8] 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MpTamperASRRule_PSA_2147772288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperASRRule.PSA"
        threat_id = "2147772288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperASRRule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 1
        $x_1_2 = "-mppreference " wide //weight: 1
        $x_1_3 = {2d 00 61 00 74 00 74 00 61 00 63 00 6b 00 73 00 75 00 72 00 66 00 61 00 63 00 65 00 72 00 65 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 72 00 75 00 6c 00 65 00 73 00 5f 00 69 00 64 00 73 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 00 61 00 74 00 74 00 61 00 63 00 6b 00 73 00 75 00 72 00 66 00 61 00 63 00 65 00 72 00 65 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 72 00 75 00 6c 00 65 00 73 00 5f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 73 00 20 00 [0-8] 61 00 75 00 64 00 69 00 74 00 6d 00 6f 00 64 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

