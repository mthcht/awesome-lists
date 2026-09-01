rule Trojan_Win32_HostInjector_YAA_2147977279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HostInjector.YAA!MTB"
        threat_id = "2147977279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HostInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Vape421 Injector" ascii //weight: 2
        $x_2_2 = "Vape421Native.dll" ascii //weight: 2
        $x_2_3 = "Select a Java game window (Up/Down, Enter to inject, Esc to quit)" ascii //weight: 2
        $x_2_4 = "Target process is not x64; injection refused" wide //weight: 2
        $x_2_5 = "Remote LoadLibraryW did not finish within 30 second" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

