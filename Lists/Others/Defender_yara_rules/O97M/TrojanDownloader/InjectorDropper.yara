rule TrojanDownloader_O97M_InjectorDropper_SA_2147786488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/InjectorDropper.SA"
        threat_id = "2147786488"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "InjectorDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RtlFillMemory Lib \"k32.tmp\"" ascii //weight: 1
        $x_1_2 = "VirtualAlloc Lib \"k32.tmp\"" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent Lib \"k32.tmp\"" ascii //weight: 1
        $x_2_4 = "execute Lib \"k32.tmp\" Alias \"CreateThread\"" ascii //weight: 2
        $x_3_5 = "FileCopy \"C:\\windows\\system32\\kernel32.dll\", Environ(\"TEMP\") & \"\\k32.tmp\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

