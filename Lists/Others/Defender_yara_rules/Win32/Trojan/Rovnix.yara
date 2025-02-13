rule Trojan_Win32_Rovnix_SA_2147740901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rovnix.SA"
        threat_id = "2147740901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "173.208.160.45" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\VolmgrmntHome" wide //weight: 1
        $x_1_3 = "\\system32\\drivers\\01879F73.sys" wide //weight: 1
        $x_1_4 = "WINDOWS\\Temp\\MpCz01.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

