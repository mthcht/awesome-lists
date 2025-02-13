rule PWS_Win32_Bawmaq_A_2147626473_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bawmaq.A"
        threat_id = "2147626473"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bawmaq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 69 70 6f 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 6f 6d 65 70 63 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 66 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 41 42 2d 5b 4d 61 71 75 69 6e 61 5d 2d 00}  //weight: 1, accuracy: High
        $x_1_5 = "SMTP-[Maquina]-" ascii //weight: 1
        $x_1_6 = ".exe /stext C:\\winhelp.txt\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

