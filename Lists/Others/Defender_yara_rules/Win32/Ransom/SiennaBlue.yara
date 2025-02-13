rule Ransom_Win32_SiennaBlue_A_2147826196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SiennaBlue.A!dha"
        threat_id = "2147826196"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SiennaBlue"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/development/working_project/src/HolyGhostProject/" ascii //weight: 2
        $x_2_2 = "/development/src/HolyLocker/" ascii //weight: 2
        $x_2_3 = "/development/src/HolyGhostProject/" ascii //weight: 2
        $x_1_4 = "23AS32df21" ascii //weight: 1
        $x_1_5 = "http://193.56.29.123" ascii //weight: 1
        $x_1_6 = "adm-karsair" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_SiennaBlue_B_2147826198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SiennaBlue.B!dha"
        threat_id = "2147826198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SiennaBlue"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/src/HolyGhostProject/Network/network.go" ascii //weight: 2
        $x_2_2 = "/src/HolyGhostProject/MainFunc/HolyRS/HolyRS.go" ascii //weight: 2
        $x_2_3 = "/src/HolyGhost/Main/common.go" ascii //weight: 2
        $x_2_4 = "/src/HolyGhost/Main/HolyLock/locker.go" ascii //weight: 2
        $x_2_5 = "/src/HolyLocker/Main/common.go" ascii //weight: 2
        $x_2_6 = "/src/HolyLocker/Main/HolyLock/locker.go" ascii //weight: 2
        $x_1_7 = ".h0lyenc" ascii //weight: 1
        $x_1_8 = "lockertask" ascii //weight: 1
        $x_1_9 = "H0lyGh0stWebsite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

