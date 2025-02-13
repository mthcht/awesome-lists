rule Trojan_Win32_Molock_B_2147716334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Molock.B"
        threat_id = "2147716334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Molock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck " ascii //weight: 1
        $x_1_2 = "\\\\physicaldrive0" ascii //weight: 1
        $x_1_3 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_4 = "A512548E76954B6E92C21055517615B0" ascii //weight: 1
        $x_1_5 = "5F99C1642A2F4e03850721B4F5D7C3F8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

