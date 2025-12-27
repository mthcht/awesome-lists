rule Trojan_Win32_RemcosRatz_A_2147949421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRatz.A!MTB"
        threat_id = "2147949421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 ff d1 0a 9d ff 80 e2 aa ff ac 81 e2 ff 56 00 62 ff e2 8d 80 ff 80 e2 ab ff 8f 80 e2 ff e2 ac 81 ff 80 e2 8f ff 8c 80 e2 ff e2 ae 80 ff e2 00 ae ff 80 e2 8b ff ae 81 e2 ff e2 ac 81 ff 81 e2 8e ff ae 81 e2 ff e2 8c 80 ff 80 e2 ab ff ad 80 e2 ff e2 8e 80 ff 80 e2 aa ff 54 00 ae ff 81 e2 ac ff ac 80 e2 ff 80 e2 ad ff 80 e2 ac ff e2 8f 80 ff e2 8d 80 ff 6d 6f 43 ff e2 8d 80 ff e2 aa 80 ff ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

