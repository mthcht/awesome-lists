rule Trojan_Win32_UacBypass_I_2147950072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacBypass.I!MTB"
        threat_id = "2147950072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe" wide //weight: 1
        $x_1_2 = "add" wide //weight: 1
        $x_1_3 = "hkcu\\software\\classes\\ms-settings\\shell\\open\\command" wide //weight: 1
        $x_1_4 = "c:\\windows\\system32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UacBypass_PA_2147952187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacBypass.PA!MTB"
        threat_id = "2147952187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "reg add" wide //weight: 2
        $x_1_2 = "HKCU\\Environment" wide //weight: 1
        $x_1_3 = "/v windir /t REG_SZ /d" wide //weight: 1
        $x_1_4 = "/f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UacBypass_PB_2147952188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacBypass.PB!MTB"
        threat_id = "2147952188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "schtasks /Run /i /TN" wide //weight: 2
        $x_1_2 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

