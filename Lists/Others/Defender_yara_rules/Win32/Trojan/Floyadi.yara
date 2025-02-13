rule Trojan_Win32_Floyadi_A_2147709155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Floyadi.A!bit"
        threat_id = "2147709155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Floyadi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\KXOSUK" ascii //weight: 2
        $x_2_2 = "C:\\WINDOWS\\system32\\svchoct.exe" ascii //weight: 2
        $x_1_3 = "\\Ruikop.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

