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

