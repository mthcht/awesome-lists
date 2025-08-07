rule Trojan_Win32_SusRegCredsHKLM_MK_2147948693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegCredsHKLM.MK"
        threat_id = "2147948693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegCredsHKLM"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "reg.exe query HKLM /f password" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /s " ascii //weight: 1
        $n_1_6 = "823853d7-114a-4744-b265-4d0fc5a11c30" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegCredsHKLM_MK_2147948693_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegCredsHKLM.MK"
        threat_id = "2147948693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegCredsHKLM"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "reg.exe query HKLM /f password" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /s " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

