rule TrojanSpy_Win32_QQWare_D_2147724960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/QQWare.D!bit"
        threat_id = "2147724960"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "QQWare"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5B3838F5-0C81-46D9-A4C0-6EA28CA3E942" ascii //weight: 1
        $x_1_2 = "svohost.exe" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\360safc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

