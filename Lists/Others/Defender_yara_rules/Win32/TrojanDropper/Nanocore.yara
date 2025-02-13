rule TrojanDropper_Win32_Nanocore_A_2147742709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nanocore.A"
        threat_id = "2147742709"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nanocore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6A84./7BK8" ascii //weight: 1
        $x_1_2 = "waveInAddBuffer2" ascii //weight: 1
        $x_1_3 = "EVENT_SINK_QueryInterface" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

