rule Trojan_Win32_LuxNET_SD_2147745088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LuxNET.SD!MTB"
        threat_id = "2147745088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LuxNET"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Could not detect AV" ascii //weight: 1
        $x_1_2 = "File was Executed successfully!" ascii //weight: 1
        $x_1_3 = "/C ping 1.1.1.1 -n 1 -w 5 > Nul & Del \"" ascii //weight: 1
        $x_1_4 = "You are chatting with" ascii //weight: 1
        $x_1_5 = "TW96aWxsYVxGaXJlZm94XFByb2ZpbGVz" ascii //weight: 1
        $x_1_6 = "XEdvb2dsZVxDaHJvbWVcVXNlciBEYXRhXERlZmF1bHRcTG9naW4gRGF0YQ==" ascii //weight: 1
        $x_1_7 = "[End Paste]" ascii //weight: 1
        $x_1_8 = "LuxNET RAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

