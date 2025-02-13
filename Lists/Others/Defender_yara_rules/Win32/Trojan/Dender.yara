rule Trojan_Win32_Dender_A_2147796972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dender.A"
        threat_id = "2147796972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-u:t " wide //weight: 10
        $x_10_2 = " icacls " wide //weight: 10
        $x_10_3 = " smartscreen.exe " wide //weight: 10
        $x_10_4 = "remove " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dender_B_2147796973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dender.B"
        threat_id = "2147796973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-u:t " wide //weight: 10
        $x_10_2 = " sc " wide //weight: 10
        $x_10_3 = " delete " wide //weight: 10
        $x_10_4 = " windefend " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dender_C_2147796974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dender.C"
        threat_id = "2147796974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-u:t " wide //weight: 10
        $x_10_2 = " reg " wide //weight: 10
        $x_10_3 = " notification_suppress " wide //weight: 10
        $x_10_4 = " ux configuration " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dender_D_2147796975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dender.D"
        threat_id = "2147796975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/transfer " wide //weight: 10
        $x_10_2 = "/download " wide //weight: 10
        $x_10_3 = "bypass-tamper-protection" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dender_DA_2147808388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dender.DA"
        threat_id = "2147808388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/transfer " wide //weight: 10
        $x_10_2 = "/download " wide //weight: 10
        $x_10_3 = "%temp%\\nsudo.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

