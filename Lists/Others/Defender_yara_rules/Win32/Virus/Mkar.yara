rule Virus_Win32_Mkar_I_2147708775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Mkar.I!bit"
        threat_id = "2147708775"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Mkar"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Mrak" ascii //weight: 1
        $x_2_2 = "\\Netstart\\svchost.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

