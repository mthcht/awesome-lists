rule Ransom_Win32_MegaCortex_A_2147735596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MegaCortex.A"
        threat_id = "2147735596"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MegaCortex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "M3GA-S1=" ascii //weight: 5
        $x_5_2 = "!-!_README_!-!.rtf" wide //weight: 5
        $x_2_3 = "C:\\mou_jvsoS1.log" ascii //weight: 2
        $x_2_4 = "call mou_jvsoS1-2.cmd %1% cipher wmic" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

