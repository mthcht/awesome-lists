rule Trojan_Win32_FavLoader_A_2147889539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FavLoader.A!MTB"
        threat_id = "2147889539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FavLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rundll32 favicon.jpg, #" ascii //weight: 2
        $x_1_2 = "WinExec" ascii //weight: 1
        $x_1_3 = "CreateMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

