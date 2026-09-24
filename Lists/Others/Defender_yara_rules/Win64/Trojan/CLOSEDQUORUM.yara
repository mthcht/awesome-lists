rule Trojan_Win64_CLOSEDQUORUM_DA_2147978776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CLOSEDQUORUM.DA!MTB"
        threat_id = "2147978776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CLOSEDQUORUM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "main.stealCredentials" ascii //weight: 10
        $x_10_2 = "main.createDynamicPayload" ascii //weight: 10
        $x_1_3 = "main.sendToDiscord" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "chacha20poly1305" ascii //weight: 1
        $x_1_6 = "Password" ascii //weight: 1
        $x_1_7 = "Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

