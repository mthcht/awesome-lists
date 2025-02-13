rule VirTool_WinNT_Exforel_A_2147668298_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Exforel.A"
        threat_id = "2147668298"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Exforel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 31 34 31 20 63 6d 64 20 73 68 65 6c 6c 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\.\\Pipe\\x141_stdout" ascii //weight: 1
        $x_1_3 = "hpamx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

