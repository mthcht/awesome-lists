rule BrowserModifier_Win32_Feedcath_228678_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Feedcath"
        threat_id = "228678"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Feedcath"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Internet Explorer\\Approved Extensions" wide //weight: 1
        $x_1_2 = "/fwlink/?LinkId=159651" ascii //weight: 1
        $x_10_3 = {67 00 65 00 74 00 6d 00 70 00 6f 00 66 00 66 00 65 00 72 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {67 00 65 00 74 00 66 00 6f 00 6f 00 66 00 66 00 65 00 72 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = "\\thent-team\\ie\\Binaries\\Content" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

