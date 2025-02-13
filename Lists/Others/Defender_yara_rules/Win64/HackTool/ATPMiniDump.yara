rule HackTool_Win64_ATPMiniDump_2147763347_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ATPMiniDump!lsa"
        threat_id = "2147763347"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ATPMiniDump"
        severity = "High"
        info = "lsa: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ATPMiniDump" ascii //weight: 2
        $x_2_2 = "By b4rtik & uf0" wide //weight: 2
        $x_2_3 = "Temp\\dumpert.dmp" wide //weight: 2
        $x_1_4 = "[!] You need elevated" wide //weight: 1
        $x_1_5 = "[!] Failed to create minidump," wide //weight: 1
        $x_1_6 = "[1] Checking OS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

