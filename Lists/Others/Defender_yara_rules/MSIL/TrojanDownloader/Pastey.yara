rule TrojanDownloader_MSIL_Pastey_A_2147727013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pastey.A!bit"
        threat_id = "2147727013"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pastey"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paste.ee/r/XyMDI" wide //weight: 1
        $x_1_2 = "OlpvbmUuSWRlbnRpZmllcg==" wide //weight: 1
        $x_1_3 = "V1NjcmlwdC5TaGVsbA==" wide //weight: 1
        $x_1_4 = "U3RhcnR1cA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

