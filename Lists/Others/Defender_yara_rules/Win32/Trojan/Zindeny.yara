rule Trojan_Win32_Zindeny_A_2147709399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zindeny.A!bit"
        threat_id = "2147709399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zindeny"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "drivers\\zdpasscd.sys" ascii //weight: 1
        $x_1_2 = "%s\\msname.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

