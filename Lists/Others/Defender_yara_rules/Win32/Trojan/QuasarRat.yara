rule Trojan_Win32_QuasarRat_NEAI_2147843347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QuasarRat.NEAI!MTB"
        threat_id = "2147843347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://spoofer.sytes.net" ascii //weight: 5
        $x_2_2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii //weight: 2
        $x_2_3 = "Registy entrie(s) were spoofed." ascii //weight: 2
        $x_2_4 = "DisableAntiSpyware" ascii //weight: 2
        $x_2_5 = "Real-Time Protection" ascii //weight: 2
        $x_2_6 = "DisableRealtimeMonitoring" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

