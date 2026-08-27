rule Trojan_Win64_PotatoRAT_YBJ_2147977035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PotatoRAT.YBJ!MTB"
        threat_id = "2147977035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PotatoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set-MpPreference -DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_2 = "Browser password dump completed" ascii //weight: 1
        $x_1_3 = "PotatoRAT" ascii //weight: 1
        $x_1_4 = "Screen recording" ascii //weight: 1
        $x_1_5 = "keylog_start" ascii //weight: 1
        $x_1_6 = "set_clipboard" ascii //weight: 1
        $x_1_7 = "remote_desktop_start" ascii //weight: 1
        $x_1_8 = "audio_record_start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

