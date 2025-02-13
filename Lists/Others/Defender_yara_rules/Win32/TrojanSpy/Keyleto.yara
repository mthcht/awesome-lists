rule TrojanSpy_Win32_Keyleto_A_2147693815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Keyleto.A"
        threat_id = "2147693815"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Keyleto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_2 = "Windows\\CurrentVersion\\Run\\Network" wide //weight: 1
        $x_1_3 = "C:\\WINDOWS\\Network.exe" wide //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
        $x_1_5 = "ANDA TERHUBUNG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

