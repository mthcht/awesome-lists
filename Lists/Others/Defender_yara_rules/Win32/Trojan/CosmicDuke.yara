rule Trojan_Win32_CosmicDuke_CCIE_2147908906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CosmicDuke.CCIE!MTB"
        threat_id = "2147908906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CosmicDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 28 21 40 00 bf f4 20 40 00 57 ff 75 fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CosmicDuke_AD_2147981025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CosmicDuke.AD!MTB"
        threat_id = "2147981025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CosmicDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 10 0f b6 c9 8d 8c 0d 6e ff ff ff 8a 19 88 18 88 11 0f b6 85 6c ff ff ff 40 25 1f 00 00 80 79 05 48 83 c8 e0 40}  //weight: 3, accuracy: High
        $x_2_2 = {0f b6 d2 8a 94 15 6e ff ff ff 30 14 39 47 3b 7d 7c 0f 8c 6a ff ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "select id, hostname, usernamefield, passwordfield, encryptedusername, encryptedpassword from moz_logins" ascii //weight: 1
        $x_1_4 = "Application Data\\Mozilla\\Firefox\\Profiles" ascii //weight: 1
        $x_1_5 = "Application Data\\Thunderbird\\Profiles" ascii //weight: 1
        $x_1_6 = "BotGenStudio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

