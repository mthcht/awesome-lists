rule Backdoor_Win64_CopperTube_A_2147971908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CopperTube.A!dha"
        threat_id = "2147971908"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CopperTube"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c start /b powershell -c \"%s\"" ascii //weight: 1
        $x_1_2 = "About SopraVPN" ascii //weight: 1
        $x_1_3 = "Software\\WireGuard" ascii //weight: 1
        $x_1_4 = "main.checkForAdminDesktop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

