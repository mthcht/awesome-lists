rule Trojan_Win32_Oclot_A_2147742517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oclot.A!dha"
        threat_id = "2147742517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oclot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\bugrpt.log" ascii //weight: 1
        $x_1_2 = "Torchwood" ascii //weight: 1
        $x_1_3 = "blackmoon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

