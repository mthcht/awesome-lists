rule Backdoor_MacOS_ChillyHell_A_2147952213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ChillyHell.A!MTB"
        threat_id = "2147952213"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ChillyHell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ModuleBackconnectShell" ascii //weight: 1
        $x_1_2 = "UnknownServiceManagerInstallLogic" ascii //weight: 1
        $x_1_3 = "IsInstalledAsDaemon" ascii //weight: 1
        $x_1_4 = "InstallToShell" ascii //weight: 1
        $x_1_5 = "CreateServiceManagerLoadCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_ChillyHell_B_2147952214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ChillyHell.B!MTB"
        threat_id = "2147952214"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ChillyHell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 68 01 00 00 4d 89 cc 4d 89 c6 48 89 f3 80 39 00 0f 84 ad 00 00 00 49 89 cf 49 89 d5 0f b6 07 48 89 c1 48 d1 e9 24 01 48 89 7d b8 48 8b 57 08 48 89 d6 48 0f 44 f1 48 85 f6}  //weight: 1, accuracy: High
        $x_1_2 = "TaskCreateBackConnectShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_ChillyHell_C_2147952215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ChillyHell.C!MTB"
        threat_id = "2147952215"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ChillyHell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 f7 f9 48 89 85 f0 fe ff ff 48 8b 8d f0 fe ff ff 48 8b 45 f0 48 89 08 48 8b 8d f0 fe ff ff 48 8b 45 f0 48 89 48 10 48 8b 8d f0 fe ff ff 48 8b 45 f0 48 89 48 30 48 8b 8d f0 fe ff ff 48 8b 45 f0 48 89 48 20 c6 45 ef 01 48 8b 7d e0}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 81 ec b0 00 00 00 48 89 7d f8 48 89 75 f0 c6 45 ef 00 48 8b 7d f8 48 8d b5 58 ff ff ff e8 63 1b 00 00 83 f8 00 0f 85 1e 00 00 00 48 8b 8d 78 ff ff ff 48 8b 45 f0 48 89 08 48 8b 4d 88 48 8b 45 f0 48 89 48 20 c6 45 ef 01 8a 45 ef 24 01 0f b6 c0 48 81 c4 b0 00 00 00 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

