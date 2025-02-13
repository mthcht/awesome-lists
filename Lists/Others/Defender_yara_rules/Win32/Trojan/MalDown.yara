rule Trojan_Win32_MalDown_SA_2147817533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalDown.SA"
        threat_id = "2147817533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalDown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "system.net.webclient" wide //weight: 1
        $x_1_3 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 [0-80] 25 00 74 00 65 00 6d 00 70 00 25 00}  //weight: 1, accuracy: Low
        $x_1_4 = "wmic" wide //weight: 1
        $x_1_5 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-5] 63 00 61 00 6c 00 6c 00 [0-5] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MalDown_SB_2147916319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalDown.SB"
        threat_id = "2147916319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalDown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-255] 63 00 75 00 72 00 6c 00 [0-255] 2d 00 6a 00 6b 00 6f 00 73 00 77 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%{filename_effective}" wide //weight: 1
        $x_1_3 = "\\appdata\\local\\temp" wide //weight: 1
        $x_1_4 = "-k http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

