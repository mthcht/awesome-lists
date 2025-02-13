rule PWS_Win32_Ygebanel_A_2147642111_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ygebanel.A"
        threat_id = "2147642111"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ygebanel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80}  //weight: 2, accuracy: High
        $x_1_2 = "Entre no Yahoo" ascii //weight: 1
        $x_1_3 = "-contatos.txt" ascii //weight: 1
        $x_1_4 = "hotsendd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

