rule VirTool_Win64_Lsassy_B_2147933622_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Lsassy.B"
        threat_id = "2147933622"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Lsassy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dumpmethod.dllinject" ascii //weight: 10
        $x_10_2 = "dumpmethod.ppldum" ascii //weight: 10
        $x_10_3 = "dumpmethod.edrsandblast" ascii //weight: 10
        $x_5_4 = "dumpmethod.rdrleakdiag" ascii //weight: 5
        $x_5_5 = "dumpmethod.sqldumper" ascii //weight: 5
        $x_1_6 = "minidump.streams.SystemMemoryInfoStream" ascii //weight: 1
        $x_1_7 = "minidump.streams.TokenStream" ascii //weight: 1
        $x_1_8 = "minidump.minidumpfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

