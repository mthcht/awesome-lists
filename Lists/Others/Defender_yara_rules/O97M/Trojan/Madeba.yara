rule Trojan_O97M_Madeba_NIT_2147955441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Madeba.NIT!MTB"
        threat_id = "2147955441"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Madeba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Magic number = 0x5A4D" ascii //weight: 2
        $x_2_2 = "Target process image base address" ascii //weight: 2
        $x_2_3 = "WriteProcessMemory(structProcessInformation.hProcess" ascii //weight: 2
        $x_2_4 = "ReadProcessMemory(structProcessInformation.hProcess" ascii //weight: 2
        $x_2_5 = "ResumeThread(structProcessInformation.hThread)" ascii //weight: 2
        $x_1_6 = "CREATE_SUSPENDED" ascii //weight: 1
        $x_1_7 = "PAGE_EXECUTE_READWRITE" ascii //weight: 1
        $x_1_8 = "exec Bypass" ascii //weight: 1
        $x_1_9 = "Writing PE sections" ascii //weight: 1
        $x_1_10 = "://github.com/itm4n/VBA-RunPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

