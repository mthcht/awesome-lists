rule BrowserModifier_Win32_Ellikic_158657_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Ellikic"
        threat_id = "158657"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Ellikic"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "www.ilikeclick.com/track" ascii //weight: 4
        $x_3_2 = "SOFTWARE\\Microsoft\\dll_1_lasttime" ascii //weight: 3
        $x_2_3 = "<iframe src=\"%s\" width=0 height=0></iframe>" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

