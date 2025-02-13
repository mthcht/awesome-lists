rule Trojan_Win32_Szevil_A_2147729692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Szevil.A"
        threat_id = "2147729692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Szevil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".RegWrite \"HKEY_CURRENT_USER\\Software\\ZeroEvil\", result, \"REG_SZ\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

