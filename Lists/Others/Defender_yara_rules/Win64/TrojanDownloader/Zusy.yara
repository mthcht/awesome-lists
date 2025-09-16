rule TrojanDownloader_Win64_Zusy_RPA_2147928955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Zusy.RPA!MTB"
        threat_id = "2147928955"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "GET /livi.bin" ascii //weight: 10
        $x_10_2 = "4Vx and Set" ascii //weight: 10
        $x_10_3 = "[+] Algo %d Botes" ascii //weight: 10
        $x_10_4 = "[+] Nanai" ascii //weight: 10
        $x_10_5 = {5c 44 61 74 61 5c 53 6f 6c 75 74 69 6f 6e 73 5c [0-48] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "ResumeThread" ascii //weight: 1
        $x_1_8 = "OpenProcess" ascii //weight: 1
        $x_1_9 = "CreateRemoteThread" ascii //weight: 1
        $x_1_10 = "WS2_32.dll" ascii //weight: 1
        $x_1_11 = "Microsoft Corporation. All rights reserved." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Zusy_RPB_2147928968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Zusy.RPB!MTB"
        threat_id = "2147928968"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "76"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 45 54 20 2f ?? ?? ?? ?? 2e 62 69 6e}  //weight: 10, accuracy: Low
        $x_10_2 = "4Vx and Set" ascii //weight: 10
        $x_10_3 = "[+] Connect to %s:%s" ascii //weight: 10
        $x_10_4 = "[+] Sent %ld Bytes" ascii //weight: 10
        $x_10_5 = "[+] Received %d Bytes" ascii //weight: 10
        $x_10_6 = "[+] Connection closed" ascii //weight: 10
        $x_10_7 = {5c 44 61 74 61 5c 53 6f 6c 75 74 69 6f 6e 73 5c [0-48] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "ResumeThread" ascii //weight: 1
        $x_1_10 = "OpenProcess" ascii //weight: 1
        $x_1_11 = "CreateRemoteThread" ascii //weight: 1
        $x_1_12 = "WS2_32.dll" ascii //weight: 1
        $x_1_13 = "Microsoft Corporation. All rights reserved." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Zusy_AUZ_2147952322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Zusy.AUZ!MTB"
        threat_id = "2147952322"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b c8 48 8d 15 87 36 01 00 48 8b d8 ff 15 ?? ?? ?? ?? 48 8d 15 67 36 01 00 48 8b cb 48 89 05 25 00 02 00 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = "195.66.27.77" ascii //weight: 2
        $x_1_3 = "84.21.189.158" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

