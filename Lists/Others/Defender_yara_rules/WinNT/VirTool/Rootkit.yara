rule VirTool_WinNT_Rootkit_A_2147621517_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkit.A"
        threat_id = "2147621517"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "agony rootkit" ascii //weight: 1
        $x_1_2 = "%s -p process.exe     : hide the process" ascii //weight: 1
        $x_1_3 = {89 44 24 10 c7 44 24 0c 16 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 dc ff 22 00 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 83 ec 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

