rule Backdoor_Win32_Dograft_A_2147595124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dograft.A"
        threat_id = "2147595124"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dograft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegisterNetworkPlugClient" ascii //weight: 1
        $x_1_2 = "1234567890.vxd" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_3_4 = "\\\\.\\pipe\\DogCraftX" ascii //weight: 3
        $x_1_5 = "WM_Hooks_RunFD" ascii //weight: 1
        $x_3_6 = "MAGICLINK" ascii //weight: 3
        $x_1_7 = "<systemdir>" ascii //weight: 1
        $x_3_8 = "Server: Microsoft-IIS/5.0" ascii //weight: 3
        $x_3_9 = "/%d.asp?%c HTTP/1.1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

