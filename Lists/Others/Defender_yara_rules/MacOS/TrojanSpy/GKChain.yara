rule TrojanSpy_MacOS_GKChain_A_2147836797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MacOS/GKChain.A!MTB"
        threat_id = "2147836797"
        type = "TrojanSpy"
        platform = "MacOS: "
        family = "GKChain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "usa.4jrb7xn8rxsn8o4lghk7lx6vnvnvazva" ascii //weight: 5
        $x_1_2 = "JKEncrypt doEncryptStr" ascii //weight: 1
        $x_1_3 = "JKEncrypt doEncryptHex" ascii //weight: 1
        $x_1_4 = ".keychain" ascii //weight: 1
        $x_1_5 = "%@/MobileDevice/Provisioning Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MacOS_GKChain_D_2147906330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MacOS/GKChain.D!MTB"
        threat_id = "2147906330"
        type = "TrojanSpy"
        platform = "MacOS: "
        family = "GKChain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "usa.4jrb7xn8rxsn8o4lghk7lx6vnvnvazva" ascii //weight: 6
        $x_1_2 = "JKEncrypt doEncryptStr" ascii //weight: 1
        $x_1_3 = ".keychain" ascii //weight: 1
        $x_1_4 = "completionTaskContainsGkeyStandardHow:absoluteFilePath" ascii //weight: 1
        $x_1_5 = "ncryptDirectoriesResponseOctet" ascii //weight: 1
        $x_1_6 = "postDataWithEncrypt3desData" ascii //weight: 1
        $x_1_7 = "deviceIdentityServerCheck:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

