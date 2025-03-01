rule HackTool_Win64_Juicypotato_2147740472_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Juicypotato"
        threat_id = "2147740472"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Juicypotato"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JuicyPotato v%s" ascii //weight: 1
        $x_1_2 = "-l <port>: COM" ascii //weight: 1
        $x_1_3 = "Priv Adjust FALSE" ascii //weight: 1
        $x_1_4 = "[+] CreateProcessWithTokenW OK" ascii //weight: 1
        $x_1_5 = "Waiting for auth..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

