rule Trojan_Win32_Kuaibpy_A_2147710202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kuaibpy.A!bit"
        threat_id = "2147710202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuaibpy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".kuaibu8.c" ascii //weight: 1
        $x_1_2 = "server.txt" ascii //weight: 1
        $x_1_3 = "DLL:pc.dll" ascii //weight: 1
        $x_1_4 = "\\TCP-file.dll" ascii //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\bug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

