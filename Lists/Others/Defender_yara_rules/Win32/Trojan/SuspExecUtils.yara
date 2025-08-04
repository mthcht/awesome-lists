rule Trojan_Win32_SuspExecUtils_MK_2147948229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExecUtils.MK"
        threat_id = "2147948229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExecUtils"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $n_1_4 = "a4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce1" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExecUtils_MK_2147948229_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExecUtils.MK"
        threat_id = "2147948229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExecUtils"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo sb_" ascii //weight: 1
        $x_1_2 = " >NUL" ascii //weight: 1
        $x_1_3 = "& exit" ascii //weight: 1
        $n_1_4 = "c4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce2" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

