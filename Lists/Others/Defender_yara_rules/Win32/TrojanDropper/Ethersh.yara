rule TrojanDropper_Win32_Ethersh_A_2147655369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ethersh.gen!A"
        threat_id = "2147655369"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ethersh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 07 2c 63 34 42 34 63 f6 d0 88 07 47 e2 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

