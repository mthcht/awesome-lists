rule Trojan_Win64_BroPass_CB_2147850816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BroPass.CB!MTB"
        threat_id = "2147850816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BroPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b ca 41 b8 00 30 00 00 48 8b d1 48 8b c8 48 ff 25}  //weight: 1, accuracy: High
        $x_1_2 = {4f 00 55 00 54 00 50 00 55 00 54 00 5f 00 42 00 49 00 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BroPass_CC_2147850819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BroPass.CC!MTB"
        threat_id = "2147850819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BroPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 8b d7 33 c9 48 8b f0 8b df ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BroPass_C_2147947414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BroPass.C!MTB"
        threat_id = "2147947414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BroPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BraveSoftware/Brave-Browser/User Data/" ascii //weight: 2
        $x_2_2 = "Google/Chrome Beta/User Data" ascii //weight: 2
        $x_2_3 = "Mozilla/Firefox/Profiles" ascii //weight: 2
        $x_2_4 = "Export passwords/cookies/history/bookmarks from browser" ascii //weight: 2
        $x_3_5 = "hack-browser-data" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

