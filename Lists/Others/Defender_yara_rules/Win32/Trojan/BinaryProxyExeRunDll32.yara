rule Trojan_Win32_BinaryProxyExeRunDll32_A_2147919259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BinaryProxyExeRunDll32.A"
        threat_id = "2147919259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BinaryProxyExeRunDll32"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rundll32.exe" wide //weight: 3
        $x_3_2 = "\\windows\\temp\\" wide //weight: 3
        $x_3_3 = ".dll" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

