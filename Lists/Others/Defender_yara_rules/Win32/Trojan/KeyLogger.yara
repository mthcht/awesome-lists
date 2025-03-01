rule Trojan_Win32_keyLogger_DJ_2147845372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/keyLogger.DJ!MTB"
        threat_id = "2147845372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "keyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "klogger" ascii //weight: 1
        $x_1_3 = "main.keyLogger" ascii //weight: 1
        $x_1_4 = "main.windowLogger" ascii //weight: 1
        $x_1_5 = "github.com/kbinani/screenshot.init" ascii //weight: 1
        $x_1_6 = "github.com/kbinani/screenshot.CaptureDisplay" ascii //weight: 1
        $x_1_7 = "github.com/kbinani/screenshot.getDesktopWindow" ascii //weight: 1
        $x_1_8 = "github.com/kbinani/screenshot.GetDisplayBounds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

