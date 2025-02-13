rule PWS_Win32_Gypthoy_A_2147648014_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gypthoy.A"
        threat_id = "2147648014"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gypthoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Submit\" name=\"B1\"><input type=\"reset" ascii //weight: 1
        $x_1_2 = "<p>LOG:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" ascii //weight: 1
        $x_1_3 = "<input type=\"text\" name=\"pcname" ascii //weight: 1
        $x_1_4 = "<title>Serial</title>" ascii //weight: 1
        $x_1_5 = "Are You Sure You Want To Clear Log ???" wide //weight: 1
        $x_1_6 = "Keyspy/post" ascii //weight: 1
        $x_1_7 = {43 6f 6d 6d 61 6e 64 39 00 04 01 07 00 53 65 61 72 63 68 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

