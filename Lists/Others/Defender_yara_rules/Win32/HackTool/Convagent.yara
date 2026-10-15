rule HackTool_Win32_Convagent_A_2147980343_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Convagent.A!MTB"
        threat_id = "2147980343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/lo announce(\"HWID Banned: %s [%d]\")" ascii //weight: 1
        $x_1_2 = "BitPatch_banned_hwids.txt" ascii //weight: 1
        $x_1_3 = "// Add banned HWIDs here (one per line). Example:" ascii //weight: 1
        $x_1_4 = "[+] Config Loaded -> Port: %d" ascii //weight: 1
        $x_1_5 = "*** SERVER: IP [%s] MATCHED BANNED HWID [%s]" ascii //weight: 1
        $x_1_6 = "[-] FATAL ERROR: BitPatch.dll is missing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

