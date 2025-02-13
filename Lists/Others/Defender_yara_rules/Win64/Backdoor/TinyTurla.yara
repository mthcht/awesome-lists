rule Backdoor_Win64_TinyTurla_RHA_2147908330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TinyTurla.RHA!MTB"
        threat_id = "2147908330"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyTurla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Title:" wide //weight: 1
        $x_1_2 = "Hosts" wide //weight: 1
        $x_1_3 = "Security" wide //weight: 1
        $x_1_4 = "TimeLong" wide //weight: 1
        $x_1_5 = "MachineGuid" wide //weight: 1
        $x_1_6 = "WinHttpSetOption" ascii //weight: 1
        $x_1_7 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_8 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 77 00 36 00 34 00 74 00 69 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_2_9 = {50 45 00 00 64 86 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 0c 00 1e 00 00 00 12 00 00 00 00 00 00 50 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_TinyTurla_RHB_2147908336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TinyTurla.RHB!MTB"
        threat_id = "2147908336"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyTurla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 75 74 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = {2f 72 73 73 ?? 6f 6c 64 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "killme" ascii //weight: 1
        $x_1_4 = "Endpoint changed" ascii //weight: 1
        $x_1_5 = "Client Ready" ascii //weight: 1
        $x_1_6 = "lu.bat" ascii //weight: 1
        $x_1_7 = "delkill /F" ascii //weight: 1
        $x_2_8 = {50 45 00 00 64 86 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 1d 00 e4 02 00 00 a8 01 00 00 00 00 00 ?? ?? 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_TinyTurla_RHC_2147914343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TinyTurla.RHC!MTB"
        threat_id = "2147914343"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyTurla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nsiproxy" wide //weight: 1
        $x_1_2 = "Beep" wide //weight: 1
        $x_1_3 = "netbt" wide //weight: 1
        $x_1_4 = "ActiveComputerName" wide //weight: 1
        $x_1_5 = "svchost.exe" ascii //weight: 1
        $x_1_6 = "taskmgr" ascii //weight: 1
        $x_1_7 = ".tmp" ascii //weight: 1
        $x_1_8 = ".sav" ascii //weight: 1
        $x_1_9 = ".upd" ascii //weight: 1
        $x_1_10 = "shell." ascii //weight: 1
        $x_2_11 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 08 00 00 be 05 00 00 b4 02 00 00 00 00 00 1c cb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

