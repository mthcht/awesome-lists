rule Trojan_Win64_Dcstl_PDE_2147827840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dcstl.PDE!MTB"
        threat_id = "2147827840"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 2c 0b 72 ?? ?? ?? 70 17 28 ?? ?? ?? 06 02 73 ?? ?? ?? 0a 25 11 07 6f ?? ?? ?? 0a 25 11 04 6f ?? ?? ?? 0a 25 18}  //weight: 1, accuracy: Low
        $x_1_2 = {11 11 11 12 9a 13 13 11 13 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 39 ?? ?? ?? 00 02 7b ?? ?? ?? 04 7e ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 0b 02}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 25 16 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 7d ?? ?? ?? 04 16 13 09 72 ?? ?? ?? 70 13 0a 17 13 0b 16 13 0c 28 ?? ?? ?? 0a 13 0d 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dcstl_MA_2147834233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dcstl.MA!MTB"
        threat_id = "2147834233"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 30 48 8b f1 8a c2 24 08 c0 e0 02 44 0f b6 d0 44 8b ca 41 8a c2 0c 80 44 0f b6 c0 41 81 e1 00 40 00 00 45 0f 44 c2 41 0f b6 c8 8a c1 0c 10 0f b6 d8 80 e2 80 0f 44 d9 48 8b ce ff 15}  //weight: 10, accuracy: High
        $x_2_2 = "node.exe" wide //weight: 2
        $x_2_3 = "silence all process warnings" ascii //weight: 2
        $x_2_4 = "internal/blocklist" ascii //weight: 2
        $x_2_5 = "Node.js" wide //weight: 2
        $x_2_6 = "challengePassword" ascii //weight: 2
        $x_2_7 = "internal/assert/calltracker" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dcstl_ND_2147966316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dcstl.ND!MTB"
        threat_id = "2147966316"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 03 48 85 c0 74 09 e8 7e ff 00 00 85 c0 75 0b 48 83 c3 08 48 3b df 75 e6 33 c0}  //weight: 2, accuracy: High
        $x_1_2 = "DISCORD TOKENS CAPTURED" ascii //weight: 1
        $x_1_3 = "Microsoft\\Edge Beta\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_4 = "Mozilla\\Firefox\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

