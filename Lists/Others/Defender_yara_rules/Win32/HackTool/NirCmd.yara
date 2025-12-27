rule HackTool_Win32_NirCmd_AMTB_2147957491_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NirCmd!AMTB"
        threat_id = "2147957491"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NirCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saked/NSudoLG.exe" ascii //weight: 1
        $x_1_2 = "saked/nircmd.exe" ascii //weight: 1
        $x_1_3 = "saked/cecho.exe" ascii //weight: 1
        $x_1_4 = "saked/same.zip" ascii //weight: 1
        $x_1_5 = "saked/7z.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

