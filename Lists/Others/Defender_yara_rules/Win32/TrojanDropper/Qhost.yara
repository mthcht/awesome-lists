rule TrojanDropper_Win32_Qhost_GP_2147655756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Qhost.GP"
        threat_id = "2147655756"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "04\\ku4uqt.jpg" ascii //weight: 1
        $x_1_2 = "04\\i1.exe" ascii //weight: 1
        $x_1_3 = "04\\test.bat" ascii //weight: 1
        $x_1_4 = "01\\ololo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

