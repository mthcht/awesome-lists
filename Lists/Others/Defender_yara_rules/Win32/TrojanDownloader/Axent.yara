rule TrojanDownloader_Win32_Axent_A_2147620605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Axent.A"
        threat_id = "2147620605"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Axent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Pxocess32Next" ascii //weight: 5
        $x_5_2 = "CreazeProcessA" ascii //weight: 5
        $x_5_3 = "uSlmon.dll" ascii //weight: 5
        $x_5_4 = "PXocess32First" ascii //weight: 5
        $x_2_5 = "IXXPLORE.EXE" ascii //weight: 2
        $x_2_6 = "xsxsmxax.EXE" ascii //weight: 2
        $x_2_7 = "/babynot/" ascii //weight: 2
        $x_1_8 = "Poi&er(" ascii //weight: 1
        $x_2_9 = "%u%d%u%d" ascii //weight: 2
        $x_2_10 = "%s%s%s?%s=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Axent_B_2147621243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Axent.B"
        threat_id = "2147621243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Axent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Pxocess32Next" ascii //weight: 5
        $x_5_2 = "CreaqeProcessA" ascii //weight: 5
        $x_5_3 = "uzlmon.dll" ascii //weight: 5
        $x_5_4 = "PXocess32First" ascii //weight: 5
        $x_2_5 = "IXXPLORE.EXE" ascii //weight: 2
        $x_2_6 = "qsxsmxaq.EXE" ascii //weight: 2
        $x_2_7 = "/babynot/" ascii //weight: 2
        $x_1_8 = "Poi&er(" ascii //weight: 1
        $x_2_9 = "%u%d%u%d" ascii //weight: 2
        $x_2_10 = "%s%s%s?%s=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

