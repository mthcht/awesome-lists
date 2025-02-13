rule SoftwareBundler_Win32_PaintPulse_222169_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/PaintPulse"
        threat_id = "222169"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "PaintPulse"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/install  /affid=adscube_upcleaner" wide //weight: 1
        $x_1_2 = "Bundle.exe" wide //weight: 1
        $x_1_3 = "popisetup.exe" wide //weight: 1
        $x_1_4 = "kurulum.exe" wide //weight: 1
        $x_1_5 = "somont.exe" wide //weight: 1
        $x_1_6 = "microsofsetup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

