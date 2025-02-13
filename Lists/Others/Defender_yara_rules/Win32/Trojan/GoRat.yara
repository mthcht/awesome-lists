rule Trojan_Win32_GoRat_DA_2147844252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoRat.DA!MTB"
        threat_id = "2147844252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "Spark/client/core.screenshot" ascii //weight: 1
        $x_1_3 = "Spark/client/core.GetMacAddress" ascii //weight: 1
        $x_1_4 = "Spark/client/core.GetCPUInfo" ascii //weight: 1
        $x_1_5 = "Spark/client/core.GetRAMInfo" ascii //weight: 1
        $x_1_6 = "Spark/client/core.lock" ascii //weight: 1
        $x_1_7 = "Spark/client/core.killTerminal" ascii //weight: 1
        $x_1_8 = "Spark/client/core.uploadFiles" ascii //weight: 1
        $x_1_9 = "Spark/client/core.killProcess" ascii //weight: 1
        $x_1_10 = "Spark/client/core.shutdown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

