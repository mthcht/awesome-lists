rule Trojan_Win32_SusDLLSearchOrderl_MK_2147948691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDLLSearchOrderl.MK"
        threat_id = "2147948691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDLLSearchOrderl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "rundll32" ascii //weight: 1
        $x_1_5 = "phonehome_main " ascii //weight: 1
        $x_1_6 = "phoneHome" ascii //weight: 1
        $x_1_7 = "\\\\.\\pipe\\move" ascii //weight: 1
        $n_1_8 = "bb7f4c43-f62b-4ef9-8d04-041690b03d08" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDLLSearchOrderl_MK_2147948691_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDLLSearchOrderl.MK"
        threat_id = "2147948691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDLLSearchOrderl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "rundll32" ascii //weight: 1
        $x_1_5 = "phonehome_main " ascii //weight: 1
        $x_1_6 = "phoneHome" ascii //weight: 1
        $x_1_7 = "\\\\.\\pipe\\move" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

