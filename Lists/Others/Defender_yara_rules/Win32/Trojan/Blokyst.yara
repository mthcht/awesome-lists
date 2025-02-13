rule Trojan_Win32_Blokyst_A_2147742638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blokyst.A"
        threat_id = "2147742638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blokyst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\FastLoader\\ConsoleApp1\\obj\\Debug\\usps.pdb" ascii //weight: 1
        $x_1_2 = "OnkyoblasterOS X-f5.99" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

