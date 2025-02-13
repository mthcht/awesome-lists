rule TrojanDropper_Win32_BrightEyes_A_2147741597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/BrightEyes.A!dha"
        threat_id = "2147741597"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "BrightEyes"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoadModule proxy_cgi_module modules/mod_proxy_cgi.so" ascii //weight: 1
        $x_2_2 = "/index/inc1ude/conn/" ascii //weight: 2
        $x_1_3 = {2d 00 75 00 00 00 00 00 2d 00 55 00 00 00 00 00 2d 00 69 00 00 00 00 00 2d 00 49 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_2_4 = "xcpoy %s %s /E /Y" ascii //weight: 2
        $x_1_5 = "rd /S /Q %s" ascii //weight: 1
        $x_1_6 = "%s SP%d (Build %d) %s" ascii //weight: 1
        $x_3_7 = "\\project\\owl\\isapi\\" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

