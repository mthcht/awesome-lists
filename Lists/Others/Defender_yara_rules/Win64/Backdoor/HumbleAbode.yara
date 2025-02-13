rule Backdoor_Win64_HumbleAbode_A_2147918432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/HumbleAbode.A!dha"
        threat_id = "2147918432"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "HumbleAbode"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/agentError/%s/%i" wide //weight: 1
        $x_1_2 = "/endTask/%s" wide //weight: 1
        $x_1_3 = "/askForCome/%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_HumbleAbode_B_2147918433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/HumbleAbode.B!dha"
        threat_id = "2147918433"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "HumbleAbode"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreatePipe g_hChildStd_OUT_Rd & g_hChildStd_OUT_Wr failed!" ascii //weight: 1
        $x_1_2 = "SetHandleInformation g_hChildStd_IN_Wr failed!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

