rule TrojanSpy_Win32_Satcoiru_A_2147650203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Satcoiru.A"
        threat_id = "2147650203"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Satcoiru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "00205F4741445652592B4322" wide //weight: 4
        $x_4_2 = "18595C51534F1F462A40" wide //weight: 4
        $x_2_3 = "90637D7366600264036C7C5920435F435656" wide //weight: 2
        $x_2_4 = "00205D535657535544274330" wide //weight: 2
        $x_2_5 = "0024795C565A42584403462A455E" wide //weight: 2
        $x_2_6 = "00285E5D5853555058215F2757555945" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

