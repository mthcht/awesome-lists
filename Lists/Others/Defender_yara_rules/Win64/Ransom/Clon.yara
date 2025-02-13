rule Ransom_Win64_Clon_ISG_2147817166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clon.ISG!MSR"
        threat_id = "2147817166"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clon"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!_READ_!!!.RTF" wide //weight: 1
        $x_1_2 = ".CI_0P" ascii //weight: 1
        $x_1_3 = "WNETView" wide //weight: 1
        $x_1_4 = "Beidso3jfdsjhjkHU#e2342fwr2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

