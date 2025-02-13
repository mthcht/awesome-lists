rule Backdoor_Win32_Mizzmo_A_2147658378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mizzmo.A"
        threat_id = "2147658378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mizzmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IZZM345M0" ascii //weight: 1
        $x_1_2 = "/syncasset.html" ascii //weight: 1
        $x_1_3 = "updatesync.html?id=%s" ascii //weight: 1
        $x_1_4 = "DOWNFL1" ascii //weight: 1
        $x_1_5 = "CMDRUN1 tasklist" ascii //weight: 1
        $x_1_6 = "TeamPrtsKey" ascii //weight: 1
        $x_1_7 = {51 55 49 54 42 44 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Mizzmo_B_2147709007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mizzmo.B"
        threat_id = "2147709007"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mizzmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7d f8 00 75 0d 8b 55 08 8b cb c1 e9 10 ff 45 08 88 0a c1 e3 08 48 75 e7}  //weight: 10, accuracy: High
        $x_2_2 = ".com:443" ascii //weight: 2
        $x_1_3 = "/update/checkstart.html" ascii //weight: 1
        $x_1_4 = "https://docs.google.com/viewer?url=%s&embedded=true" ascii //weight: 1
        $x_1_5 = "net.exe group \"Admins." ascii //weight: 1
        $x_1_6 = "http://%s/files/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

