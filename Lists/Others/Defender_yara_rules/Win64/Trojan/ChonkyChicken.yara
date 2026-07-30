rule Trojan_Win64_ChonkyChicken_GXQ_2147974748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChonkyChicken.GXQ!MTB"
        threat_id = "2147974748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChonkyChicken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d2 b9 02 00 00 00 e8 ?? ?? ?? ?? 49 89 c4 48 83 f8 ?? 0f 84 ?? ?? ?? ?? 31 c0 48 8d bc 24 ?? ?? ?? ?? b9 26 00 00 00 f3 48 ab 4c 8d b4 24 ?? ?? ?? ?? 4c 89 e1 c7 84 24 ?? ?? ?? ?? 30 01 00 00 4c 89 f2}  //weight: 10, accuracy: Low
        $x_2_2 = "WebSocket handshake to CDP failed. Path: " ascii //weight: 2
        $x_2_3 = "webSocketDebuggerUrl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ChonkyChicken_GXR_2147974841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChonkyChicken.GXR!MTB"
        threat_id = "2147974841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChonkyChicken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 44 24 50 ff 15 ?? ?? ?? ?? 48 8d 84 24 ?? ?? ?? ?? 48 8d 54 24 ?? 48 89 c1 48 89 44 24 ?? ff 15 ?? ?? ?? ?? 31 c0 b9 12 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "keylog_start" ascii //weight: 1
        $x_1_3 = "chrome_extract" ascii //weight: 1
        $x_1_4 = "chrome_upload" ascii //weight: 1
        $x_1_5 = "wpad_capture.ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

