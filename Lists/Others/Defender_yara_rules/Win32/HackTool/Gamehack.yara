rule HackTool_Win32_Gamehack_G_2147743547_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Gamehack.G!MSR"
        threat_id = "2147743547"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamehack"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Couldn't find csgo.exe!" ascii //weight: 1
        $x_1_2 = "justGlow.pdb" ascii //weight: 1
        $x_1_3 = "GLOWHACK:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Gamehack_G_2147743547_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Gamehack.G!MSR"
        threat_id = "2147743547"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamehack"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Exploits\\Exploit-API\\Release\\exploit-main.pdb" ascii //weight: 5
        $x_1_2 = "Roblox/exploit crashed." ascii //weight: 1
        $x_1_3 = "Keep crashing? Make sure Roblox is closed in the task manager" ascii //weight: 1
        $x_1_4 = "Please rejoin the game and retry" ascii //weight: 1
        $x_1_5 = "script=Instance.new(\"LocalScript\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Gamehack_MD_2147788160_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Gamehack.MD!MTB"
        threat_id = "2147788160"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamehack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 38 6a 00 6a 01 88 45 f8 8d 45 f8 50 57 ff 71 04 ff d3 8b 4d f4 47 8b 45 f0 83 ee 01 75 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

