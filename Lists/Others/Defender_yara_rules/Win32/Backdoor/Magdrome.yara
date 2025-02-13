rule Backdoor_Win32_Magdrome_A_2147678345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Magdrome.A"
        threat_id = "2147678345"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Magdrome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d3 c1 e2 10 0b ca 8b 54 24 2c 89 0c aa 8b f7 83 c5 01 8b c8 2b f0 8d 9b 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "DRIVER={SQL Server};SERVER=%s,%d;UID=%s;PWD=%s" ascii //weight: 1
        $x_1_3 = "_guama_" ascii //weight: 1
        $x_1_4 = "74.82.166.115" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

