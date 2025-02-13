rule TrojanSpy_Win32_Chaori_A_2147656482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Chaori.A"
        threat_id = "2147656482"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FJn:MK9gMKDTEKUiO6rkMK8" ascii //weight: 1
        $x_1_2 = "N7E:P3ah@%Q%Qk" ascii //weight: 1
        $x_1_3 = "DlbPDK9jQJY*O%|TM6HTP79hM%9UOJ5lK5" ascii //weight: 1
        $x_1_4 = "D:rBI44TD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

