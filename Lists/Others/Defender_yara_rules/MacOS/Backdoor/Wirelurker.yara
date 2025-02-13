rule Backdoor_MacOS_Wirelurker_A_2147734486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Wirelurker.A"
        threat_id = "2147734486"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Wirelurker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 75 6e 2e 73 68 00 2f 75 73 72 2f 6c 6f 63 61 6c 2f 6d 61 63 68 6f 6f 6b 2f 6d 61 63 68 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 6f 6e 74 4d 61 70 31 2e 63 66 67 00 2f 62 69 6e 2f 73 68 00 2d 72 66 00 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 73 74 61 72 74 2e 73 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 67 6c 6f 62 61 6c 75 70 64 61 74 65 2e 70 6c 69 73 74 00 6e 6f 00 79 65 73 00 68 74 74 70 3a 2f 2f 77 77 77 2e [0-30] 2e 63 6f 6d 2f 6d 61 63 5f 6c 6f 67 2f 3f 61 70 70 69 64 3d 25 40 2b 2b 25 40 2b 2b 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_MacOS_Wirelurker_A_2147734486_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Wirelurker.A"
        threat_id = "2147734486"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Wirelurker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/DerivedData/myProject-bempnuunysxoafcdeokuvvfigmze/" ascii //weight: 2
        $x_1_2 = "/System/Library/LaunchDaemons/com.apple.MailServiceAgentHelper.plist" ascii //weight: 1
        $x_1_3 = "rm -rf /var/db/launchd.db/com.apple.launchd/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

