rule Trojan_Win64_Bzub_BN_2147980362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bzub.BN!MTB"
        threat_id = "2147980362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bzub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "User Data\\Default\\Local Storage\\leveldb" ascii //weight: 2
        $x_1_2 = "=== CLIPBOARD ===" ascii //weight: 1
        $x_1_3 = "encrypted_key" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "DiscordBot" ascii //weight: 1
        $x_1_6 = "c2.getkaiju.cc" ascii //weight: 1
        $x_1_7 = "tokens cookies wifi clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

