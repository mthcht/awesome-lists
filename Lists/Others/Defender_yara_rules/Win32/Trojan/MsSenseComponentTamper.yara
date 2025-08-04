rule Trojan_Win32_MsSenseComponentTamper_A_2147948286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MsSenseComponentTamper.A"
        threat_id = "2147948286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MsSenseComponentTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "takeown" wide //weight: 1
        $x_1_2 = " /f " wide //weight: 1
        $x_1_3 = "mssense.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MsSenseComponentTamper_B_2147948287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MsSenseComponentTamper.B"
        threat_id = "2147948287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MsSenseComponentTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icacls" wide //weight: 1
        $x_1_2 = "MsSense.dll" wide //weight: 1
        $x_1_3 = " /grant " wide //weight: 1
        $x_1_4 = ":F" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MsSenseComponentTamper_C_2147948288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MsSenseComponentTamper.C"
        threat_id = "2147948288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MsSenseComponentTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icacls" wide //weight: 1
        $x_1_2 = "mssense.exe" wide //weight: 1
        $x_1_3 = " /deny " wide //weight: 1
        $x_1_4 = " everyone:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

