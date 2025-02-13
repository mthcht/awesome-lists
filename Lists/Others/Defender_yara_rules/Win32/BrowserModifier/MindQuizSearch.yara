rule BrowserModifier_Win32_MindQuizSearch_150044_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/MindQuizSearch"
        threat_id = "150044"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "MindQuizSearch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4d 69 6e 64 51 75 69 7a 53 65 61 72 63 68 54 6f 6f 6c 62 61 72 00 70 72 65 66 28 22 65 78 74 65 6e 73 69 6f 6e 73 2e 73 65 61 72 63 68 74 6f 6f 6c 62 61 72}  //weight: 1, accuracy: High
        $x_1_2 = "track.zugo.com/cgi-bin/debug.py?filename=mindquizsetup-silent-i_accept&url=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

