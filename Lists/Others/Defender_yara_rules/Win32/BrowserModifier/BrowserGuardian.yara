rule BrowserModifier_Win32_BrowserGuardian_203491_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/BrowserGuardian"
        threat_id = "203491"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "BrowserGuardian"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4B5DC379-ED06-4552-A736-414A1570C24F" wide //weight: 1
        $x_1_2 = "Oops, something changed in your proxy settings" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

