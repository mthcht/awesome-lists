rule PWS_Win32_Qiper_A_2147628216_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qiper.A"
        threat_id = "2147628216"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://file.qip.ru/file/" ascii //weight: 1
        $x_1_2 = "QIP\\Profiles\\" ascii //weight: 1
        $x_1_3 = "title=\"AIM\"" ascii //weight: 1
        $x_1_4 = "ReadProcessMemory" ascii //weight: 1
        $x_1_5 = "GetWindowTextA" ascii //weight: 1
        $x_1_6 = {51 49 50 20 2d 20 d1 ef ee ea ee e9 ed ee e5 20 ee e1 f9 e5 ed e8 e5 21}  //weight: 1, accuracy: High
        $x_10_7 = {8a 45 ff 04 e0 2c 5f 72 06 04 bf 2c 40 73 1c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

