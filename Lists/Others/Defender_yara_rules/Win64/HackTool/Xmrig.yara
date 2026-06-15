rule HackTool_Win64_Xmrig_YSD_2147971616_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Xmrig.YSD!MTB"
        threat_id = "2147971616"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Xmrig"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pool_wallet" ascii //weight: 1
        $x_1_2 = "make sure you set \"algo\" or \"coin\" option" ascii //weight: 1
        $x_1_3 = "your IP is banned" ascii //weight: 1
        $x_1_4 = "generate key derivation for miner signature" ascii //weight: 1
        $x_1_5 = "XMRig miner" wide //weight: 1
        $x_1_6 = "xmrig.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

