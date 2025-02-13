rule Ransom_Win32_MzRevenge_SK_2147753176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MzRevenge.SK!MTB"
        threat_id = "2147753176"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MzRevenge"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MZREVENGE" wide //weight: 10
        $x_10_2 = "How Do I Recover My Files (Readme).txt" wide //weight: 10
        $x_10_3 = "/C sc config \"AppCheck\" start=disabled" wide //weight: 10
        $x_10_4 = "OneCopyMutex" wide //weight: 10
        $x_10_5 = "/C vssadmin delete shadows /all /quiet" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

