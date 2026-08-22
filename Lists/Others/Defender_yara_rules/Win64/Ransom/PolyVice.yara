rule Ransom_Win64_PolyVice_PA_2147976801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PolyVice.PA!MTB"
        threat_id = "2147976801"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PolyVice"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".SunnyDay" ascii //weight: 1
        $x_1_2 = "!-Recovery_Instructions-!.html" ascii //weight: 1
        $x_1_3 = "Recovery.txt" ascii //weight: 1
        $x_1_4 = ".rans_recovery" ascii //weight: 1
        $x_5_5 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

