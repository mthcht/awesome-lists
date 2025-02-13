rule Trojan_Win32_Donvba_A_2147718026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donvba.A"
        threat_id = "2147718026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donvba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GtD2F9xgYLx3D3RGvpekLXJLtCUF0L0o1z1E" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

