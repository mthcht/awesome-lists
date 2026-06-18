rule Ransom_Win64_LockScreen_PGBD_2147969402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockScreen.PGBD!MTB"
        threat_id = "2147969402"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4f 00 6f 00 6f 00 70 00 73 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 20 00 54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 66 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 3a 00 [0-32] 3e 00 69 00 6e 00 66 00 6f 00 2d 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 74 00 78 00 74 00 20 00 26 00 20 00 61 00 74 00 74 00 72 00 69 00 62 00 20 00 2d 00 68 00 20 00 2b 00 73 00 20 00 2b 00 72 00 20 00 69 00 6e 00 66 00 6f 00 2d 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 74 00 78 00 74 00}  //weight: 4, accuracy: Low
        $x_2_2 = "Windows blocked!" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockScreen_AYB_2147971247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockScreen.AYB!MTB"
        threat_id = "2147971247"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "WowkNetlockMutex" ascii //weight: 4
        $x_1_2 = "Your computer has been locked" ascii //weight: 1
        $x_1_3 = "SYSTEM LOCKED" ascii //weight: 1
        $x_1_4 = "Task Manager is blocked" ascii //weight: 1
        $x_1_5 = "Keyboard and mouse are disabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockScreen_LRI_2147971854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockScreen.LRI!MTB"
        threat_id = "2147971854"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ooops, your files have been encrypted!" ascii //weight: 1
        $x_2_2 = "Your important files are encrypted." ascii //weight: 2
        $x_3_3 = "TermedRansom" ascii //weight: 3
        $x_4_4 = "termed.lol" ascii //weight: 4
        $x_5_5 = "Google Chromekey1" ascii //weight: 5
        $x_6_6 = "lsass.exe" ascii //weight: 6
        $x_7_7 = "Discord Token Tool/1.0" ascii //weight: 7
        $x_8_8 = "To decrypt your files, contact us on Discord:" ascii //weight: 8
        $x_9_9 = "are no longer accessible because they have been encrypted." ascii //weight: 9
        $x_10_10 = "Your files are encrypted!" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

