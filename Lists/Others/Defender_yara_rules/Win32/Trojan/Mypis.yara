rule Trojan_Win32_Mypis_CB_2147838919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mypis.CB!MTB"
        threat_id = "2147838919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mypis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6D9A7CEE-054A-437D-99EF-DD7C77E001FD" ascii //weight: 1
        $x_1_2 = "LoadResource" ascii //weight: 1
        $x_1_3 = "shell" ascii //weight: 1
        $x_1_4 = "Inced.BBC" ascii //weight: 1
        $x_1_5 = "WahOpenCurrentThread" ascii //weight: 1
        $x_1_6 = "WahDisableNonIFSHandleSupport" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

