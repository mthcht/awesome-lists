rule TrojanDownloader_MSIL_Clipper_A_2147837872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Clipper.A!MTB"
        threat_id = "2147837872"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAcABvAHcAZQByAHMAaABlAGwAbAAgAC0AVw" wide //weight: 2
        $x_2_2 = "BpAG4AZABvAHcAUwB0AHkAbABlACAASABpAGQAZABlAG4AIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACA" wide //weight: 2
        $x_2_3 = "BlACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzAD" wide //weight: 2
        $x_2_4 = "AFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAE0AZQBzAHMAYQBnAGUAQgBvAHgA" wide //weight: 2
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "-EncodedCommand" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

