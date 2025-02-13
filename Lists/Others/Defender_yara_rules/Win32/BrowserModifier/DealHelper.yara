rule BrowserModifier_Win32_DealHelper_14806_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/DealHelper"
        threat_id = "14806"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "DealHelper"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ads1.dealhelper.com" ascii //weight: 1
        $x_1_2 = "RedirectSystem/URLLINK/DELETE" ascii //weight: 1
        $x_1_3 = "userid=%hS&ld=%hS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

