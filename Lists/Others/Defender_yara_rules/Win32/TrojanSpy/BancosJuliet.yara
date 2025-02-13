rule TrojanSpy_Win32_BancosJuliet_2147690992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BancosJuliet"
        threat_id = "2147690992"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BancosJuliet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Juliet\\Desktop" wide //weight: 1
        $x_1_2 = "\\BHOBJ\\flash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

