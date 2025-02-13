rule Ransom_Win32_Maui_A_2147825995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maui.A"
        threat_id = "2147825995"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maui"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 42 55 50 01 00 00 00 a2 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "maui.key" ascii //weight: 1
        $x_1_3 = "by <Godhead> using -maui option" ascii //weight: 1
        $x_1_4 = "Usage: maui [-ptx] [PATH]" ascii //weight: 1
        $x_1_5 = "demigod.key" ascii //weight: 1
        $x_1_6 = "Self Melt (Default: No)" ascii //weight: 1
        $x_1_7 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_8 = "Encrypt[%s]: %s" ascii //weight: 1
        $x_1_9 = {83 c4 1c 81 3f 54 50 52 43 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

