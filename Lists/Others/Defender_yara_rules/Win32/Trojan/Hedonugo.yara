rule Trojan_Win32_Hedonugo_2147930183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hedonugo"
        threat_id = "2147930183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hedonugo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b d0 48 8b c1 49 8b 0a 49 8b 52 08 4d 8b 42 10 4d 8b 4a 18 4c 8b d1 0f 05}  //weight: 1, accuracy: High
        $x_1_2 = "create afd_device_handle failed" ascii //weight: 1
        $x_1_3 = "szKasperskyFile" ascii //weight: 1
        $x_1_4 = "afdDeviceName" ascii //weight: 1
        $x_1_5 = "impersonation_handle" ascii //weight: 1
        $x_1_6 = "pipe_handle_for_spray" ascii //weight: 1
        $x_1_7 = "CreateSocket is failed" ascii //weight: 1
        $x_1_8 = {5c 45 78 70 6c 6f 69 74 4b 69 74 5c [0-255] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_9 = "LPE_AFD" ascii //weight: 1
        $x_1_10 = "DestroyEnv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

