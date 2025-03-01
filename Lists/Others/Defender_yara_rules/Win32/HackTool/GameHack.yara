rule HackTool_Win32_GameHack_2147712662_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GameHack"
        threat_id = "2147712662"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\HWID.txt" ascii //weight: 1
        $x_1_2 = "PointBlank.exe" ascii //weight: 1
        $x_1_3 = "//indocheat.xyz" ascii //weight: 1
        $x_1_4 = "TrayIcon.cpp" ascii //weight: 1
        $x_1_5 = "PSAPI.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_GameHack_J_2147752398_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GameHack.J!MSR"
        threat_id = "2147752398"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FLiNGTrainer.com" ascii //weight: 1
        $x_1_2 = "bbs.3dmgame.com" ascii //weight: 1
        $x_1_3 = "flingtrainer.com/tag/monster-hunter-world" ascii //weight: 1
        $x_1_4 = "copy constructor closure" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_GameHack_B_2147755559_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GameHack.B!MTB"
        threat_id = "2147755559"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Settings\\Save.ini" wide //weight: 1
        $x_1_2 = "VIRTUALIZER_END" wide //weight: 1
        $x_1_3 = "VIRTUALIZER_START" wide //weight: 1
        $x_1_4 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_5 = "Bot E-PIN :" ascii //weight: 1
        $x_1_6 = "VLC media player" ascii //weight: 1
        $x_1_7 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_8 = "ACME_ISTIRAP.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_GameHack_KP_2147756557_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GameHack.KP"
        threat_id = "2147756557"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "malar\\Visual Studio\\CG_Loader\\CG_Loader\\obj\\x86\\Release\\CG_Loader.pdb" ascii //weight: 1
        $x_1_2 = "CG_Loader" ascii //weight: 1
        $x_1_3 = "PUBG_Lite_Hack" ascii //weight: 1
        $x_1_4 = "WOLFTU_Multihack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_GameHack_MM_2147898343_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GameHack.MM"
        threat_id = "2147898343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PointBlank.exe" ascii //weight: 1
        $x_1_2 = "zepetto.online" ascii //weight: 1
        $x_1_3 = "Gagal Download Cheat" ascii //weight: 1
        $x_1_4 = "vipenjoyers.xyz" ascii //weight: 1
        $x_1_5 = "vvipegn.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

