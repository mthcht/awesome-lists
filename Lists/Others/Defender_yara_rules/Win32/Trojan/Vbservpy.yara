rule Trojan_Win32_Vbservpy_A_2147710495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbservpy.A!bit"
        threat_id = "2147710495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbservpy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AD:\\MIHAILO\\Programs\\Moje\\Life4Hack RAT\\Rat\\Server" wide //weight: 1
        $x_1_2 = "shutdown -s -t 00" wide //weight: 1
        $x_1_3 = "server.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

