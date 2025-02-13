rule Ransom_Win32_Rapowsom_A_2147741251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rapowsom.A"
        threat_id = "2147741251"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapowsom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-executionpolicy bypass" wide //weight: 1
        $x_1_3 = "-windowstyle hidden" wide //weight: 1
        $x_1_4 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-10] 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {28 00 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6f 00 2e 00 66 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 72 00 65 00 61 00 64 00 61 00 6c 00 6c 00 74 00 65 00 78 00 74 00 28 00 27 00 [0-2] 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-255] 2e 00 74 00 6d 00 70 00 27 00 29 00 29 00 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 [0-4] 27 00 2c 00 27 00 27 00 29 00 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Rapowsom_B_2147741281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rapowsom.B"
        threat_id = "2147741281"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapowsom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-executionpolicy bypass" wide //weight: 1
        $x_1_3 = "-windowstyle hidden" wide //weight: 1
        $x_1_4 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-10] 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {28 00 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6f 00 2e 00 66 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 72 00 65 00 61 00 64 00 61 00 6c 00 6c 00 74 00 65 00 78 00 74 00 28 00 27 00 [0-2] 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-255] 2e 00 74 00 6d 00 70 00 27 00 29 00 29 00 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 21 00 27 00 2c 00 27 00 27 00 29 00 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

