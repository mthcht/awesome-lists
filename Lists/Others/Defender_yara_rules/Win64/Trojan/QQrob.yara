rule Trojan_Win64_QQrob_RPY_2147904647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QQrob.RPY!MTB"
        threat_id = "2147904647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QQrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b c0 c7 44 24 20 04 00 00 00 33 d2 41 b9 00 10 00 00 48 8b ce ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "vantacheats.rip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

