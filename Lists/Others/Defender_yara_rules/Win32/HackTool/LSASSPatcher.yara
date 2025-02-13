rule HackTool_Win32_LSASSPatcher_A_2147819368_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LSASSPatcher.A"
        threat_id = "2147819368"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LSASSPatcher"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Offset of g_fParameter_UseLogonCredential: 0x%08x" wide //weight: 1
        $x_1_2 = "Offset of g_IsCredGuardEnabled: 0x%08x" wide //weight: 1
        $x_1_3 = "Base address of wdigest.dll: 0x%016p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

