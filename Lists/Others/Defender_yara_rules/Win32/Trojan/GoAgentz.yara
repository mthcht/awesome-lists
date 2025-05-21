rule Trojan_Win32_GoAgentz_Z_2147941848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoAgentz.Z!MTB"
        threat_id = "2147941848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoAgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "client finished" ascii //weight: 1
        $x_1_2 = "server finished" ascii //weight: 1
        $x_1_3 = "key expansion" ascii //weight: 1
        $x_1_4 = "extended master secret" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "Go buildinf" ascii //weight: 1
        $x_1_7 = "username" ascii //weight: 1
        $x_1_8 = "password" ascii //weight: 1
        $x_1_9 = "AddrPort" ascii //weight: 1
        $x_1_10 = "sockaddr" ascii //weight: 1
        $x_1_11 = {48 8b 84 24 48 05 00 00 31 c9 87 88 30 05 00 00 90 b9 01 00 00 00 f0 0f c1 88 68 03 00 00 48 8b 84 24 28 05 00 00 48 8b 0d 54 dc 4e 00 48 89 0c 24 48 89 44 24 08 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

