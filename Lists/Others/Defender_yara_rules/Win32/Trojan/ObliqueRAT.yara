rule Trojan_Win32_ObliqueRAT_A_2147750566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ObliqueRAT.A!MSR"
        threat_id = "2147750566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ObliqueRAT"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Oblique" ascii //weight: 5
        $x_5_2 = "C:\\ProgramData\\auto.txt" ascii //weight: 5
        $x_5_3 = "185.117.73.222" ascii //weight: 5
        $x_1_4 = "Artifact" ascii //weight: 1
        $x_1_5 = "Vince" ascii //weight: 1
        $x_1_6 = "Serena" ascii //weight: 1
        $x_1_7 = "JOHNSON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

