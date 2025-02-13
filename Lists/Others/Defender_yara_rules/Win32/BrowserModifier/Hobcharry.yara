rule BrowserModifier_Win32_Hobcharry_155871_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Hobcharry"
        threat_id = "155871"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Hobcharry"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 14 01 02 04 08 c7 44 24 18 10 20 40 90 c7 44 24 1c ff fe fc f8 c7 44 24 20 f0 e0 c0 80}  //weight: 1, accuracy: High
        $x_1_2 = {41 44 56 42 48 4f 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = ".?AVCAdvBHOClass@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

