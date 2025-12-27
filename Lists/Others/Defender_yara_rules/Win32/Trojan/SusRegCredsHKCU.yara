rule Trojan_Win32_SusRegCredsHKCU_MK_2147948694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegCredsHKCU.MK"
        threat_id = "2147948694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegCredsHKCU"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "reg.exe query HKCU /f password" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /s " ascii //weight: 1
        $n_1_6 = "bfd813f3-7fc9-4d61-a592-5900ea1d4fab" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegCredsHKCU_MK_2147948694_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegCredsHKCU.MK"
        threat_id = "2147948694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegCredsHKCU"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "reg.exe query HKCU /f password" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /s " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegCredsHKCU_AM_2147948935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegCredsHKCU.AM"
        threat_id = "2147948935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegCredsHKCU"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "reg.exe query HKCU /f password" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /s " ascii //weight: 1
        $n_1_6 = "ac06e39e-7876-4ba3-beee-42bd80ff362d" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

