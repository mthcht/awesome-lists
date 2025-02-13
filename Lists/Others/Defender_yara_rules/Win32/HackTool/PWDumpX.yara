rule HackTool_Win32_PWDumpX_2147741329_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PWDumpX"
        threat_id = "2147741329"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PWDumpX"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PWDumpX" ascii //weight: 1
        $x_1_2 = "[+] Username:     \"%s\"" ascii //weight: 1
        $x_1_3 = "[+] # of Threads: \"64\"" ascii //weight: 1
        $x_1_4 = "//reedarvin.thearvins.com/" ascii //weight: 1
        $x_1_5 = "%s\\ADMIN$\\system32\\Dump" ascii //weight: 1
        $x_1_6 = "PWCache.txt" ascii //weight: 1
        $x_1_7 = "LSASecrets.txt" ascii //weight: 1
        $x_1_8 = "PWHistoryHashes.txt" ascii //weight: 1
        $x_1_9 = "PWHashes.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

