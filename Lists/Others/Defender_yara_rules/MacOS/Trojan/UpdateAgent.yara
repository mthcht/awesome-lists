rule Trojan_MacOS_UpdateAgent_A_2147796946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/UpdateAgent.A"
        threat_id = "2147796946"
        type = "Trojan"
        platform = "MacOS: "
        family = "UpdateAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$(ioreg -ad2 -c IOPlatformExpertDevice|xmllint --xpath '//key[.=\"IOPlatformUUID\"]" ascii //weight: 1
        $x_1_2 = "curl --retry 5 -H \"Content-Type: application/json; charset=UTF-8\" -X POST -d" ascii //weight: 1
        $x_1_3 = "xattr -r -d com.apple.quarantine /tmp/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_UpdateAgent_B_2147798505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/UpdateAgent.B!MTB"
        threat_id = "2147798505"
        type = "Trojan"
        platform = "MacOS: "
        family = "UpdateAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=\"$(ioreg -ad2 -c IOPlatformExpertDevice | xmllint --xpath '//key[.=\"IOPlatformUUID\"]/following-sibling::*[1]/text()' -)\";" ascii //weight: 1
        $x_1_2 = {3d 24 28 63 75 72 6c 20 2d 2d 63 6f 6e 6e 65 63 74 2d 74 69 6d 65 6f 75 74 20 39 30 30 20 2d 4c 20 22 68 74 74 70 73 3a 2f 2f [0-80] 29 3b 65 76 61 6c 20 22 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_UpdateAgent_A_2147807682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/UpdateAgent.A!MTB"
        threat_id = "2147807682"
        type = "Trojan"
        platform = "MacOS: "
        family = "UpdateAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 e5 48 83 ec 20 89 7d fc 48 89 75 f0 8b 7d fc e8 ?? ?? ?? 00 83 f8 00 0f ?? ?? ?? ?? 00 48 ?? ?? ?? ?? 00 00 48 63 4d fc 8b 54 88 3c 89 d0 48 23 45 f0 48 83 f8 00 40 0f 95 c6 40 80 f6 ff 40 80 f6 ff 40 88 75 ef}  //weight: 2, accuracy: Low
        $x_2_2 = {89 ca 48 8d bd 68 ff ff ff 48 8d b5 60 ff ff ff 48 89 95 f8 fd ff ff e8 d2 06 00 00 48 8d 45 88 48 89 c7 48 89 85 f0 fd ff ff e8 6f 06 00 00 48 89 85 38 ff ff ff 48 8d bd 40 ff ff ff 48 8d b5 38 ff ff ff 48 8b 95 f8 fd ff ff e8 9e 06 00 00 48 8b b5 68 ff ff ff 48 8b 95 40 ff ff ff 48 8b bd f0 fd ff ff e8 94 04 00 00 48 89 85 e8 fd ff ff e9 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_UpdateAgent_C_2147808788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/UpdateAgent.C!MTB"
        threat_id = "2147808788"
        type = "Trojan"
        platform = "MacOS: "
        family = "UpdateAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 e5 48 81 ec f0 00 00 00 c7 45 fc 00 00 00 00 48 8d 35 21 37 00 00 48 8d 45 e0 48 89 c7 48 89 85 28 ff ff ff e8 ?? ?? ?? 00 48 8d 7d b0 48 8b b5 28 ff ff ff e8 24 32 00 00 e9 00 00 00 00 48 8d 7d c8 48 8d 75 b0 e8 12 f8 ff ff e9 00 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 e5 48 89 7d f8 40 80 e6 01 40 88 75 f7 48 8b 45 f8 f6 45 f7 01 48 89 45 e8 0f ?? ?? ?? ?? 00 48 8b 45 e8 48 8b 48 08 48 8b 10 48 0b 0a 48 89 0a e9 ?? ?? ?? 00 48 8b 45 e8 48 8b 48 08 48 81 f1 ff ff ff ff 48 8b 10 48 23 0a 48 89 0a 48 8b 45 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

