rule Trojan_Win32_MalWmicShadowCopyDel_AA_2147957005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalWmicShadowCopyDel.AA"
        threat_id = "2147957005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalWmicShadowCopyDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 6d 00 69 00 63 00 [0-16] 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-16] 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MalWmicShadowCopyDel_AB_2147957006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalWmicShadowCopyDel.AB"
        threat_id = "2147957006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalWmicShadowCopyDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "shadowcopy" wide //weight: 1
        $x_1_3 = "delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

