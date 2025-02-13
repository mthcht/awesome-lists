rule BrowserModifier_Win32_Hijacker_G_155824_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Hijacker.G"
        threat_id = "155824"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Hijacker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{03CA0716-9418-4F23-BE60-F9779FB4B4FD}" wide //weight: 1
        $x_1_2 = {4a 53 5f 48 69 6a 61 63 6b 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "LIBID_JS_HijackLib" ascii //weight: 1
        $x_1_4 = "JS_HijackModule" ascii //weight: 1
        $x_1_5 = "javascript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

