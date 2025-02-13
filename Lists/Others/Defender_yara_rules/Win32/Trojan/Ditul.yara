rule Trojan_Win32_Ditul_C_2147597674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ditul.C"
        threat_id = "2147597674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {30 11 83 c1 01 80 39 00 75 f6}  //weight: 20, accuracy: High
        $x_1_2 = "Qwav)Ecajp>$Ik~mhhe+1*4$,Smj`ksw?$Q?$Sm" ascii //weight: 1
        $x_1_3 = "Gegla)Gkjpvkh>$jk)gegla" ascii //weight: 1
        $x_1_4 = "Gkjjagpmkj>$Ghkwa" ascii //weight: 1
        $x_1_5 = "Referer: test" ascii //weight: 1
        $x_1_6 = "Vzz~|p/5@fpg(" ascii //weight: 1
        $x_1_7 = "AwVwpguB`{d{~wuw" ascii //weight: 1
        $x_1_8 = "elementclient.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ditul_B_2147598599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ditul.B"
        threat_id = "2147598599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 50 e8 ?? ?? 00 00 83 c4 04 80 38 00 8b c8 74 0e 8a 54 24 08 30 11 83 c1 01 80 39 00 75 f6 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "F`xEaqfmDf{wqggPqvas]zr{fyu`}{z" ascii //weight: 1
        $x_1_3 = "KUvdrYvzrsXu}rtcdKTr{^ySeaZvg" ascii //weight: 1
        $x_1_4 = "F`xPqg`{fmEaqfmPqvasVarrqf" ascii //weight: 1
        $x_1_5 = "KUvdrYvzrsXu}rtcdKTr{D@^Y]" ascii //weight: 1
        $x_1_6 = "F`xWfqu`qEaqfmPqvasVarrqf" ascii //weight: 1
        $x_1_7 = "NcEaqfm]zr{fyu`}{zDf{wqgg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

