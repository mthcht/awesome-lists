rule Backdoor_AndroidOS_Ztorg_B_2147829884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Ztorg.B!MTB"
        threat_id = "2147829884"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Ztorg"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 40 2d e9 3c 10 9f e5 08 d0 4d e2 14 30 8d e2 01 10 9f e7 a8 40 81 e2 03 20 a0 e1 10 10 9d e5 04 00 a0 e1 04 30 8d e5 81 94 00 eb 04 10 a0 e1 0a 00 a0 e3 81 94 00 eb 08 d0 8d e2 10 40 bd e8 10 d0 8d e2}  //weight: 1, accuracy: High
        $x_1_2 = {1c 68 3e 4b 79 44 20 1c eb 58 1b 68 05 93 3c 4b eb 58 1b 68 06 93 3b 4b eb 58 1b 68 07 93 3a 4b eb 58 1f 68 ff f7 8f fe 38 4a 39 4b 06 1c 31 1c 7b 44 7a 44 20 1c ff f7 b1 fe 31 1c 02 1c 20 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_AndroidOS_Ztorg_A_2147830760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Ztorg.A!xp"
        threat_id = "2147830760"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Ztorg"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "checkAppChmod" ascii //weight: 1
        $x_1_2 = "checkInstallRecoveryEtc" ascii //weight: 1
        $x_1_3 = "/data/local/tmp/.catr.apk" ascii //weight: 1
        $x_1_4 = "/data/local/tmp/busybox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

