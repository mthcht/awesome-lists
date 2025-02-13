rule Trojan_Win64_XDRKillRustz_A_2147918681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XDRKillRustz.A!MTB"
        threat_id = "2147918681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XDRKillRustz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rust-xdr-killer" ascii //weight: 1
        $x_1_2 = {56 48 83 ec 20 4c 89 c0 48 89 ce 49 81 f9 ff ff ff 7f 41 b8 ff ff ff 7f 4d 0f 42 c1 48 8b 0a 48 89 c2 45 31 c9 ff 15 15 5b 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

