rule BrowserModifier_Win32_Accoona_17901_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Accoona"
        threat_id = "17901"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Accoona"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 53 65 61 72 63 68 41 73 73 69 73 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "http://www.accoona.com/" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Accoona" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

