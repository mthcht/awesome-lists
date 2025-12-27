rule Trojan_Win64_KillWin_SX_2147959665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillWin.SX!MTB"
        threat_id = "2147959665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[main] Step 1: Gathering environment info" ascii //weight: 2
        $x_2_2 = "[main] Step 2: Checking environment condition" ascii //weight: 2
        $x_2_3 = "[main] Step 3: User environment detected. Executing payload" ascii //weight: 2
        $x_2_4 = "[main] Payload executed. Exiting program." ascii //weight: 2
        $x_2_5 = "[main] Step 3: Sandbox environment detected. Exiting program." ascii //weight: 2
        $x_1_6 = "Registry logging is DISABLED (BENIGN_DISABLE_REGISTRY=1)" ascii //weight: 1
        $x_1_7 = "TASKROUTINE_DISABLE_REGISTRY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

