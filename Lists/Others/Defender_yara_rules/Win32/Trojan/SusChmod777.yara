rule Trojan_Win32_SusChmod777_MK_2147948692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusChmod777.MK"
        threat_id = "2147948692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusChmod777"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "icacls" ascii //weight: 1
        $x_1_5 = "sbd.bin" ascii //weight: 1
        $x_1_6 = "/grant Everyone:F" ascii //weight: 1
        $n_1_7 = "dt7f4c43-f62b-4ef9-8d04-041690b03d09" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusChmod777_MK_2147948692_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusChmod777.MK"
        threat_id = "2147948692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusChmod777"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $x_1_4 = "icacls" ascii //weight: 1
        $x_1_5 = "sbd.bin" ascii //weight: 1
        $x_1_6 = "/grant Everyone:F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

