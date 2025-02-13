rule TrojanDownloader_MSIL_Samll_GM_2147716457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Samll.GM!bit"
        threat_id = "2147716457"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samll"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aHR0cDovL3NpdGVkZXZlbG9wZXIuaXI" wide //weight: 1
        $x_1_2 = {61 00 47 00 68 00 6a 00 4c 00 6d 00 56 00 34 00 5a 00 51 00 3d 00 3d 00 [0-6] 77 00 69 00 6e 00 68 00 6c 00 70 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "U09GVFdBUkVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXFJ1bg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

