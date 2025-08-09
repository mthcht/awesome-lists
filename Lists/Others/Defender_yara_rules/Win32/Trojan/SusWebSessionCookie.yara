rule Trojan_Win32_SusWebSessionCookie_MK_2147948887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWebSessionCookie.MK"
        threat_id = "2147948887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWebSessionCookie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "& copy" ascii //weight: 1
        $x_1_5 = "\\User Data\\" ascii //weight: 1
        $n_1_6 = "ba06e39e-7876-4ba3-beee-42bd80ff362f" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusWebSessionCookie_MK_2147948887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWebSessionCookie.MK"
        threat_id = "2147948887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWebSessionCookie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "& copy" ascii //weight: 1
        $x_1_5 = "\\User Data\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

