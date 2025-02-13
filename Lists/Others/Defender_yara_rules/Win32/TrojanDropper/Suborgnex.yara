rule TrojanDropper_Win32_Suborgnex_A_2147650571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Suborgnex.A"
        threat_id = "2147650571"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Suborgnex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "168668168731415176417B0E62B2E" ascii //weight: 4
        $x_2_2 = "764217597346781C709BB4779E9D" ascii //weight: 2
        $x_2_3 = "23638793538148999F81DCCB6A" ascii //weight: 2
        $x_2_4 = "22115328357249FCFD" ascii //weight: 2
        $x_2_5 = "396667253313642DFE04DC154FA4" ascii //weight: 2
        $x_2_6 = "6739832813735D57CC9D02F67CD92" ascii //weight: 2
        $x_2_7 = "3540464265574E31149685393CF909" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

