rule Trojan_Win32_PShellTask_A_2147813407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellTask.A"
        threat_id = "2147813407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "createobject(" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = ".run" wide //weight: 1
        $x_1_6 = "powershell" wide //weight: 1
        $x_1_7 = "invoke-" wide //weight: 1
        $x_1_8 = {77 00 69 00 6e 00 64 00 6f 00 77 00 [0-2] 63 00 6c 00 6f 00 73 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

