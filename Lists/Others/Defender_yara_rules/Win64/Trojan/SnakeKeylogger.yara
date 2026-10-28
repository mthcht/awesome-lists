rule Trojan_Win64_SnakeKeylogger_SPK_2147889377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SnakeKeylogger.SPK!MTB"
        threat_id = "2147889377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b d1 41 b9 04 00 00 00 33 c9 44 8b c7 48 8b 74 24 48 48 83 c4 30 5f 48 ff 25 ac ca 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SnakeKeylogger_SS_2147981112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SnakeKeylogger.SS!MTB"
        threat_id = "2147981112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.installTask" ascii //weight: 1
        $x_1_2 = "main.hideConsole" ascii //weight: 1
        $x_1_3 = "main.connectivityWatchdog" ascii //weight: 1
        $x_1_4 = "main.GetSystemInfo" ascii //weight: 1
        $x_1_5 = "main.getHardwareInfo" ascii //weight: 1
        $x_1_6 = "main.kbToGB" ascii //weight: 1
        $x_1_7 = "main.GetGeolocation" ascii //weight: 1
        $x_1_8 = "main.GetIPAddress" ascii //weight: 1
        $x_1_9 = "main.localIPv4" ascii //weight: 1
        $x_1_10 = "main.GetNetworkAddresses" ascii //weight: 1
        $x_1_11 = "main.postWithRetry" ascii //weight: 1
        $x_1_12 = "main.VictimExists" ascii //weight: 1
        $x_1_13 = "main.CaptureScreenShot" ascii //weight: 1
        $x_1_14 = "image/png.Encode" ascii //weight: 1
        $x_1_15 = "main.getScreenShot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

