rule Backdoor_Win32_Blakken_DE_2147896083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blakken.DE!MTB"
        threat_id = "2147896083"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blakken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Resource LOSARcklES" ascii //weight: 3
        $x_3_2 = "GetLongPathNameA" ascii //weight: 3
        $x_3_3 = "msctls_hotkey" ascii //weight: 3
        $x_3_4 = "CopyEnhMetaFileA" ascii //weight: 3
        $x_3_5 = "SysReAllocStringLen" ascii //weight: 3
        $x_3_6 = "RegisterClipboardFormatA" ascii //weight: 3
        $x_3_7 = "Mot de passe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

