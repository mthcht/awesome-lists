rule Trojan_Win64_ShellCodeMarte_BZ_2147981545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeMarte.BZ!MTB"
        threat_id = "2147981545"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeMarte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 20 20 00 10 6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 8b 4d e8 51 ff 15 28 20 00 10 89 45 f8 6a 00 68 00 10 00 00 68 00 30 00 10 8b 55 f8 52 8b 45 e8 50 ff 15 2c 20 00 10 8b 4d f8 89 8d 90 fd ff ff 8d 95 d8 fc ff ff 52 8b 45 ec 50 ff 15 24 20 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

