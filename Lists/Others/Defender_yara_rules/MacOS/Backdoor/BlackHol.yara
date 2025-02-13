rule Backdoor_MacOS_BlackHol_C_2147745016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/BlackHol.C!MTB"
        threat_id = "2147745016"
        type = "Backdoor"
        platform = "MacOS: "
        family = "BlackHol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/usr/sbin/screencapture -x /Applications/" ascii //weight: 1
        $x_1_2 = "/.Data/add.app/Contents/MacOS" ascii //weight: 1
        $x_1_3 = "/.Data/add2.app/Contents/MacOS" ascii //weight: 1
        $x_1_4 = "phish2_Connected" ascii //weight: 1
        $x_1_5 = "PhishWindow.PhishWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_BlackHol_A_2147793135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/BlackHol.A!xp"
        threat_id = "2147793135"
        type = "Backdoor"
        platform = "MacOS: "
        family = "BlackHol"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 [0-8] 2f [0-7] 2f 61 64 64 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_2_2 = "Keylogger.zip" ascii //weight: 2
        $x_1_3 = {2e 69 73 69 67 68 74 63 61 70 74 75 72 65 2e 74 78 74 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 [0-8] 2f [0-7] 2f 69 73 69 67 68 74 63 61 70 74 75 72 65 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 4a 61 76 61 2f 44 61 74 61 2f [0-8] 2f 69 73 69 67 68 74 63 61 70 74 75 72 65 20 2d 77 20 31 32 30 30 20 2d 68 20 38 30 30 20 2d 74 20 6a 70 67 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 2e 4a 61 76 61 2f 44 61 74 61 2f 63 61 70 74 75 72 65 30 31 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_5 = "/.Data/add2.zip" ascii //weight: 1
        $x_1_6 = "rm -r /Applications/.JavaUpdater/.Data/.kill.zip" ascii //weight: 1
        $x_3_7 = "BlackHole RAT" ascii //weight: 3
        $x_1_8 = {54 61 6b 65 20 61 20 53 6e 61 70 73 68 6f 74 20 66 72 6f 6d 20 74 68 65 20 69 53 69 67 68 74 [0-4] 53 6c 6f 77 20 64 6f 77 6e 20 74 68 65 20 43 50 55 20 77 69 74 68 20 61 20 6c 6f 6f 70 20 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_9 = "If you want to stop the Code on the Victims Computer which enables the iSight Lamp and the Micro" ascii //weight: 1
        $x_1_10 = "AppleEventRecord" ascii //weight: 1
        $x_1_11 = "KernelPanik. System is corrupt, freezing Desktop NOW!" ascii //weight: 1
        $x_1_12 = "RemoteAddress.Get" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_BlackHol_B_2147813354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/BlackHol.B!xp"
        threat_id = "2147813354"
        type = "Backdoor"
        platform = "MacOS: "
        family = "BlackHol"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlackHole RAT" ascii //weight: 1
        $x_1_2 = "Take a Snapshot" ascii //weight: 1
        $x_1_3 = "Victims Computer which enables the iSight Lamp and the Micro" ascii //weight: 1
        $x_1_4 = "AppleEventRecord" ascii //weight: 1
        $x_1_5 = "KernelPanik. System is corrupt, freezing Desktop NOW!" ascii //weight: 1
        $x_1_6 = "RemoteAddress.Get" ascii //weight: 1
        $x_1_7 = "This feature will try to erase the full HD! It will enter the right code into the Shell Code" ascii //weight: 1
        $x_1_8 = "take and download a Screen Shot of the Victims Screen." ascii //weight: 1
        $x_1_9 = "fiphacker.txt" ascii //weight: 1
        $x_1_10 = "fipvictim.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

