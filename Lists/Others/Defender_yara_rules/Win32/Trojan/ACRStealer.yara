rule Trojan_Win32_ACRStealer_DA_2147929756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.DA!MTB"
        threat_id = "2147929756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user_pref(\"extensions.webextensions.uuids" ascii //weight: 1
        $x_1_2 = "<discarded>" ascii //weight: 1
        $x_1_3 = "steamcommunity.com" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "RmRegisterResources" ascii //weight: 1
        $x_1_6 = "InternetWriteFile" ascii //weight: 1
        $x_1_7 = "RstrtMgr.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ACRStealer_DA_2147929756_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.DA!MTB"
        threat_id = "2147929756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d a0 e5 f2 70 83 fb ff 74 29 85 db 74 11 8d 74 26 00 90 ff 14 9d a0 e5 f2 70 83 eb 01 75 f4 c7 04 24 40 7a f2 70 e8 30 99 fd ff 83 c4 18 5b c3 8d 76 00 31 c0 8d b6 00 00 00 00 89 c3 83 c0 01 8b 14 85 a0 e5 f2 70 85 d2 75 f0 eb bd 8d b4 26 00 00 00 00 8d b4 26 00 00 00 00 a1 10 30 0e 71 85 c0 74 07 c3 8d b6 00 00 00 00 c7 05 10 30 0e 71 01 00 00 00 eb 84 90 90 90 90 83 ec 1c 8b 44 24 24}  //weight: 1, accuracy: High
        $x_1_2 = {95 60 17 0e 71 75 05 88 14 08 eb 09 42 81 fa 00 01 00 00 75 e9 41 81 f9 67 f3 04 00 75 d7 89 04 24 e8 71 ff ff ff 83 c4 14 5b 5d c3 90 90 90 55 89 e5 53 8d 5d 0c 83 ec 14 c7 04 24 01 00 00 00 ff 15 3c f0 f2 70 89 5c 24 08 c7 44 24 04 00 20 0e 71 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ACRStealer_AC_2147959347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.AC!MTB"
        threat_id = "2147959347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 f0 73 12 8b 4d e8 03 4d f4 8b 55 d0 03 55 f4 8a 02 88 01 eb dd}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ACRStealer_AB_2147959576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.AB!MTB"
        threat_id = "2147959576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 26 31 c9 41 39 3c 0e 74 13 50 32 24 0e 88 64 15 00 58 41 42 38 c1 76 ec 01 ce eb e3}  //weight: 6, accuracy: High
        $x_1_2 = "rawhide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ACRStealer_NC_2147971205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.NC!MTB"
        threat_id = "2147971205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 2c 0b 31 d5 31 dd 95 88 04 19 95 43}  //weight: 3, accuracy: High
        $x_3_2 = {89 d6 c1 fe 08 29 f5 95 88 04 19 95 43}  //weight: 3, accuracy: High
        $x_3_3 = {95 88 04 19 95 96 88 44 0b 01 96 83 c3 02}  //weight: 3, accuracy: High
        $x_1_4 = "sirensfull evacuationadvertise" ascii //weight: 1
        $x_1_5 = "alertfile too large" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

