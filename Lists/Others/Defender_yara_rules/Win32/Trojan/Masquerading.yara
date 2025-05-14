rule Trojan_Win32_Masquerading_ZPA_2147934411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masquerading.ZPA"
        threat_id = "2147934411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masquerading"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".docx.exe" wide //weight: 1
        $x_1_2 = ".pdf.exe" wide //weight: 1
        $x_1_3 = ".ps1.exe" wide //weight: 1
        $x_1_4 = ".xls.vbs" wide //weight: 1
        $x_1_5 = ".xlsx.vbs" wide //weight: 1
        $x_1_6 = ".png.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Masquerading_ZPB_2147934412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masquerading.ZPB"
        threat_id = "2147934412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masquerading"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "\\powershell" wide //weight: 20
        $x_1_2 = ".doc.ps1" wide //weight: 1
        $x_1_3 = ".docx.ps1" wide //weight: 1
        $x_1_4 = ".xls.ps1" wide //weight: 1
        $x_1_5 = ".xlsx.ps1" wide //weight: 1
        $x_1_6 = ".pdf.ps1" wide //weight: 1
        $x_1_7 = ".rtf.ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Masquerading_F_2147941324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masquerading.F"
        threat_id = "2147941324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masquerading"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-96] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 74 65 6d 70 5c [0-96] 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-96] 2e 00 74 00 78 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 74 65 6d 70 5c [0-96] 2e 74 78 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_2_5 = "_main " ascii //weight: 2
        $x_2_6 = "\\\\.\\pipe\\move" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

