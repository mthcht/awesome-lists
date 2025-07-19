rule Trojan_Win32_SusOdbcconf_MK_2147946870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusOdbcconf.MK"
        threat_id = "2147946870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusOdbcconf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "odbcconf.exe /s /a {regsvr " wide //weight: 1
        $x_1_4 = "phonehome" wide //weight: 1
        $n_1_5 = "aa06e39e-7876-4ba3-beee-42bd80ff364i" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusOdbcconf_MK_2147946870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusOdbcconf.MK"
        threat_id = "2147946870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusOdbcconf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "odbcconf.exe /s /a {regsvr " wide //weight: 1
        $x_1_4 = "phonehome" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

