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

