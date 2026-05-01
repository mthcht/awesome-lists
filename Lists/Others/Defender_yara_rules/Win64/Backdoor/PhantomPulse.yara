rule Backdoor_Win64_PhantomPulse_A_2147968138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PhantomPulse.A"
        threat_id = "2147968138"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PhantomPulse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[HEIS] encrypt_text_only DONE" ascii //weight: 1
        $x_1_2 = "[CollectSysInfo] calling DetectInstalledAV" ascii //weight: 1
        $x_1_3 = "IsRunningHollowed: self=%ls is inside WinDir=%ls -> HOLLOWED" ascii //weight: 1
        $x_1_4 = "KillOldPayload: killed PID=%lu" ascii //weight: 1
        $x_1_5 = "KeylogUploadOnce: C2UploadKeylog" ascii //weight: 1
        $x_1_6 = "ProcessCommands: ELEVATE command received" ascii //weight: 1
        $x_1_7 = "[STEP 3b] Native loader DLL -> disk: OK (%d bytes, path=%ls)" ascii //weight: 1
        $x_1_8 = "PhantomInject: " ascii //weight: 1
        $x_1_9 = "DropAndExecute: InjectShellcodePhantom" ascii //weight: 1
        $x_1_10 = "inject: shellcode detected -> " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

