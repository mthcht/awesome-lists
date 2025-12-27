rule Backdoor_Win32_CosmicPulse_C_2147952834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CosmicPulse.C!dha"
        threat_id = "2147952834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/konfiguration12/" wide //weight: 10
        $x_10_2 = "C:\\TEMP\\\\schlange.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CosmicPulse_C_2147952834_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CosmicPulse.C!dha"
        threat_id = "2147952834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "reg add" wide //weight: 10
        $x_10_2 = "REG_BINARY" wide //weight: 10
        $x_10_3 = "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\.pietas" wide //weight: 10
        $x_10_4 = "ratio" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CosmicPulse_C_2147952834_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CosmicPulse.C!dha"
        threat_id = "2147952834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 63 00 20 00 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 68 00 65 00 61 00 6c 00 74 00 68 00 2f 02 02 00 20 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2f 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 20 00 6e 00 6f 00 72 00 6d 00 61 00 6c 00 20 00 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 50 00 79 00 74 00 68 00 6f 00 6e 00 33 00 38 00 2d 00 36 00 34 00 5c 00 4c 00 69 00 62 00 5c 00 6c 00 69 00 62 00 2f 16 16 00 2e 00 70 00 79 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

