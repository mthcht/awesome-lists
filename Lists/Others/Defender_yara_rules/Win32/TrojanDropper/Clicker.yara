rule TrojanDropper_Win32_Clicker_2147619892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Clicker"
        threat_id = "2147619892"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Clicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\??\\%s" ascii //weight: 10
        $x_10_2 = "installhook" ascii //weight: 10
        $x_10_3 = "\\svch0st.exe" ascii //weight: 10
        $x_10_4 = "\\cheakout.ini" ascii //weight: 10
        $x_10_5 = "598C33CB-510E-4857-9801-78F1D892879C" ascii //weight: 10
        $x_1_6 = "del %0" ascii //weight: 1
        $x_1_7 = "\\del.bat" ascii //weight: 1
        $x_1_8 = "goto delloop" ascii //weight: 1
        $x_1_9 = "ZwLoadDriver" ascii //weight: 1
        $x_1_10 = "/clcount/count.asp?action=install&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

