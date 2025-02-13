rule PWS_Win32_Remexi_YA_2147732049_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Remexi.YA!MTB"
        threat_id = "2147732049"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Remexi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "search&upload" wide //weight: 1
        $x_1_2 = "</ScreenCapture->" wide //weight: 1
        $x_1_3 = "IECrashReport.inf" wide //weight: 1
        $x_1_4 = "</*clipboard Image*>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

