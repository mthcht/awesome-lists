rule Worm_Win32_Levitiang_A_2147630530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Levitiang.A"
        threat_id = "2147630530"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Levitiang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 70 72 65 61 64 45 6d 75 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 70 72 65 61 64 41 72 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "action=Abrir carpeta para ver archivos" ascii //weight: 1
        $x_1_4 = "vigilantespread" ascii //weight: 1
        $x_1_5 = "127.0.0.1 microsoft.com" ascii //weight: 1
        $x_1_6 = "Msconfigkiller" ascii //weight: 1
        $x_1_7 = "exe.putes\\:" wide //weight: 1
        $x_1_8 = "\\downmelt.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

