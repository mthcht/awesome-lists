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
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/c start /b powershell -c \"%s\"" ascii //weight: 10
        $x_10_2 = "About SopraVPN" ascii //weight: 10
        $x_10_3 = "Software\\WireGuard" ascii //weight: 10
        $x_10_4 = "main.checkForAdminDesktop" ascii //weight: 10
        $x_1_5 = "main.openPipeFromHandleString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

