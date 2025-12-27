rule Trojan_Win32_MalPwshShadowCopyDel_AA_2147957003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalPwshShadowCopyDel.AA"
        threat_id = "2147957003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalPwshShadowCopyDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" wide //weight: 1
        $x_1_2 = "get-ciminstance win32_shadowcopy" wide //weight: 1
        $x_1_3 = "remove-ciminstance" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MalPwshShadowCopyDel_BA_2147957004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalPwshShadowCopyDel.BA"
        threat_id = "2147957004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalPwshShadowCopyDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" wide //weight: 1
        $x_1_2 = "get-wmiobject win32_shadowcopy" wide //weight: 1
        $x_1_3 = "delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

