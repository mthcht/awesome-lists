rule Backdoor_Win32_Lybsus_A_2147656650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lybsus.A"
        threat_id = "2147656650"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lybsus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSNCONTACT" wide //weight: 1
        $x_1_2 = "GETCLIP" wide //weight: 1
        $x_1_3 = "tmrCamStart" ascii //weight: 1
        $x_1_4 = "\\Uninstall.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lybsus_B_2147666820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lybsus.B"
        threat_id = "2147666820"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lybsus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tmrCamStart" ascii //weight: 1
        $x_1_2 = "MSNCONTACT" wide //weight: 1
        $x_1_3 = "SHELLHOOK" wide //weight: 1
        $x_1_4 = "Conectado" wide //weight: 1
        $x_1_5 = "RECIBIDO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

