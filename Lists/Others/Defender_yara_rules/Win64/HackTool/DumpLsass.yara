rule HackTool_Win64_Dumplsass_B_2147781994_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Dumplsass.B"
        threat_id = "2147781994"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumplsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $n_2_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -2
        $n_2_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -2, accuracy: Low
        $x_2_3 = "\\procdump64.exe" wide //weight: 2
        $x_1_4 = "-m" wide //weight: 1
        $x_1_5 = "/m" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_Dumplsass_B_2147781994_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Dumplsass.B"
        threat_id = "2147781994"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumplsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "noitcejnIyBpmuDztkM" ascii //weight: 1
        $x_1_2 = "drowssaPpmuDcorPyBpmuDztkM" ascii //weight: 1
        $x_1_3 = "CDyBpmuDztkM" ascii //weight: 1
        $x_1_4 = "eliFmaSyBpmuDztkM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

