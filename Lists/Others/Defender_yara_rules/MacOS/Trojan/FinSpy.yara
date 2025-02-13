rule Trojan_MacOS_FinSpy_A_2147764810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FinSpy.A!MTB"
        threat_id = "2147764810"
        type = "Trojan"
        platform = "MacOS: "
        family = "FinSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 55 53 42 44 61 74 61 54 79 70 65 20 7c 20 65 67 72 65 70 20 2d 69 [0-5] 4d 61 6e 75 66 61 63 74 75 72 65 72 3a 20 28 70 61 72 61 6c 6c 65 6c 73 7c 76 6d 77 61 72 65 7c 76 69 72 74 75 61 6c 62 6f 78 29}  //weight: 1, accuracy: Low
        $x_1_2 = "GIFileOps unloadAgent:" ascii //weight: 1
        $x_1_3 = "arch.zip" ascii //weight: 1
        $x_1_4 = "org.logind.ctp.archive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_FinSpy_B_2147795253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FinSpy.B!MTB"
        threat_id = "2147795253"
        type = "Trojan"
        platform = "MacOS: "
        family = "FinSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 55 53 42 44 61 74 61 54 79 70 65 20 7c 20 65 67 72 65 70 20 2d 69 [0-5] 4d 61 6e 75 66 61 63 74 75 72 65 72 3a 20 28 70 61 72 61 6c 6c 65 6c 73 7c 76 6d 77 61 72 65 7c 76 69 72 74 75 61 6c 62 6f 78 29}  //weight: 1, accuracy: Low
        $x_1_2 = "/usr/sbin/chown root:wheel /bin/chmod 06777" ascii //weight: 1
        $x_1_3 = {2f 73 62 69 6e 2f 6d 6f 75 6e 74 5f 6e 66 73 20 2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 43 6f 72 65 53 65 72 76 69 63 65 73 2f [0-32] 2e 61 70 70}  //weight: 1, accuracy: Low
        $x_1_4 = "Storage.framework /Library/Frameworks logind.plist /Library/LaunchAgents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

