rule Trojan_Win32_MBRLock_EP_2147846457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MBRLock.EP!MTB"
        threat_id = "2147846457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LG Password woshixiaoxuesheng" ascii //weight: 2
        $x_2_2 = "Your disk have a lock!!!Please enter the unlock password" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MBRLock_EQ_2147846571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MBRLock.EQ!MTB"
        threat_id = "2147846571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {16 9e 49 00 3a ab 49 00 ff ae 49 00 93 b1 49 00 b4 b1 49 00 45 e7 48 00 90 a8 40 00 50 27 41 00 90 33 41}  //weight: 3, accuracy: High
        $x_3_2 = {bd 9e 49 00 35 9f 49 00 6d 9f 49 00 39 25 49 00 4f 25 49 00 8d 25 49 00 cb 25 49 00 09 26 49 00 d4 9c 49 00 d8 a6 49}  //weight: 3, accuracy: High
        $x_2_3 = "Your disk have a lock!!!Please enter the unlock password" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MBRLock_NMB_2147899646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MBRLock.NMB!MTB"
        threat_id = "2147899646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 bc 00 00 00 33 db 39 9e ?? ?? ?? ?? 75 13 8d 85 ?? ?? ?? ?? 50 e8 0f 8f fe ff 59 89 86 ?? ?? ?? ?? 39 5e 78}  //weight: 5, accuracy: Low
        $x_1_2 = "Your disk have a lock!!!Please enter the unlock password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

