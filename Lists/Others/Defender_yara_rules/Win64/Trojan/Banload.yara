rule Trojan_Win64_Banload_EC_2147907131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Banload.EC!MTB"
        threat_id = "2147907131"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiCheat.exe" ascii //weight: 1
        $x_1_2 = "Bailey/1.0" ascii //weight: 1
        $x_1_3 = "discordapp.com" ascii //weight: 1
        $x_1_4 = "api/webhooks/1204220382094168145/anpobLsMQf9X7wjCwVR3wiFeqzMNRHXz07QubMDY6LjhZSG7apvQUUOf5T3_Z0iCvhxF" ascii //weight: 1
        $x_1_5 = "Sinister" ascii //weight: 1
        $x_1_6 = "Cheat Engine 7.5" ascii //weight: 1
        $x_1_7 = "x64dbg" ascii //weight: 1
        $x_1_8 = "FileGrab" ascii //weight: 1
        $x_1_9 = "Nigger" ascii //weight: 1
        $x_1_10 = "Beammer" ascii //weight: 1
        $x_1_11 = "Process Hacker" ascii //weight: 1
        $x_1_12 = "dexzunpacker" ascii //weight: 1
        $x_1_13 = "TLS callback: thread attach" ascii //weight: 1
        $x_1_14 = "TLS callback: process attach" ascii //weight: 1
        $x_1_15 = "TLS callback: dummy thread launched" ascii //weight: 1
        $x_1_16 = "TLSCallbackThread timeout on event creation." ascii //weight: 1
        $x_1_17 = "All seems fine for TLSCallbackProcess." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

