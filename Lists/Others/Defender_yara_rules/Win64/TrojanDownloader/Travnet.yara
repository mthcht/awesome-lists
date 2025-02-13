rule TrojanDownloader_Win64_Travnet_2147763328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Travnet!MTB"
        threat_id = "2147763328"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Travnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HfuNpevmfGjmfObnfB" ascii //weight: 1
        $x_1_2 = "hi ur in 1st" ascii //weight: 1
        $x_1_3 = "Key size is %d" ascii //weight: 1
        $x_1_4 = "Pkey Resource 2 success" ascii //weight: 1
        $x_1_5 = "Usage: inject.exe [" ascii //weight: 1
        $x_1_6 = "Usage: inject EXE [" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "EncodePointer" ascii //weight: 1
        $x_1_9 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_10 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_11 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_12 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_13 = "GetCurrentThreadId" ascii //weight: 1
        $x_1_14 = "GetSystemTimeAsFileTime" ascii //weight: 1
        $x_1_15 = "OutputDebugStringW" ascii //weight: 1
        $x_1_16 = "memset" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

