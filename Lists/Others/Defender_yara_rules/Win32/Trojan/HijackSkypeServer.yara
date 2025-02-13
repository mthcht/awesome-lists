rule Trojan_Win32_HijackSkypeServer_A_2147817507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSkypeServer.A"
        threat_id = "2147817507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSkypeServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "cmd /c" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

