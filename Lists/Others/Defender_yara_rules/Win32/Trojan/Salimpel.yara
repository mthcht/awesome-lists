rule Trojan_Win32_Salimpel_A_2147633321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salimpel.A"
        threat_id = "2147633321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salimpel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_2 = "Internet Settings\\Zones\\3\\1803" wide //weight: 1
        $x_1_3 = "HKCU\\Control Panel\\Mouse\\SwapMouseButtons" wide //weight: 1
        $x_1_4 = "-:Generation:-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

