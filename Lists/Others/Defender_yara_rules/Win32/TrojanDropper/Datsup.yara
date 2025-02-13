rule TrojanDropper_Win32_Datsup_A_2147741975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Datsup.A"
        threat_id = "2147741975"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Datsup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\dasvchost.exe" wide //weight: 1
        $x_1_2 = "C:\\WINDOWS\\sdtartup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

