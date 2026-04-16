rule HackTool_Win64_KillEDR_GH_2147963844_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/KillEDR.GH!MTB"
        threat_id = "2147963844"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "KillEDR"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Firmware\\OemHwUpd.sys" ascii //weight: 1
        $x_1_2 = "sentinelservice.exe" wide //weight: 1
        $x_1_3 = "mssense.exe" wide //weight: 1
        $x_1_4 = "sophossps.exe" wide //weight: 1
        $x_1_5 = "avastsvc.exe" wide //weight: 1
        $x_1_6 = "elastic-endpoint.exe" wide //weight: 1
        $x_1_7 = "\\\\.\\OemHwUpd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win64_KillEDR_SX_2147967182_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/KillEDR.SX!MTB"
        threat_id = "2147967182"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "KillEDR"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "moving the payload to the hollowed memory without using an API" ascii //weight: 30
        $x_20_2 = "key Decrypted after stomping, Shellcode length: %d" ascii //weight: 20
        $x_20_3 = "Hit enter to run shellcode/payload without creating a new thread" ascii //weight: 20
        $x_15_4 = "EDR/AV evasion tool" ascii //weight: 15
        $x_5_5 = "killer.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

