rule TrojanDropper_Win32_Droxpob_A_2147708011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Droxpob.A"
        threat_id = "2147708011"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Droxpob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RCHELICOPTERFTW" ascii //weight: 1
        $x_1_2 = "attrib +h C:\\TEMP\\ytmp" ascii //weight: 1
        $x_1_3 = "echo xmlhttp.Open \"GET\", \"https://www.dropbox.com/s/0tp8grbxhhau0ay/clicker.pyw?dl=1\", False >> python.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

