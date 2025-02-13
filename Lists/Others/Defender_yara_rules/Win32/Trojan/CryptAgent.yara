rule Trojan_Win32_CryptAgent_SD_2147730976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptAgent.SD!MTB"
        threat_id = "2147730976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 33 c0 b9 [0-6] ba [0-6] [0-6] 85 c0 75 [0-4] b8 01 00 00 00 eb [0-4] 33 c0 [0-6] 8b 5d fc 03 de 73 [0-6] e8 [0-6] 89 5d f8 [0-6] 85 c0 75 [0-4] [0-4] 8a 1a 80 f3 46 88 5d f7 [0-6] 8b 5d f8 8b fb 8a 5d f7 88 1f [0-6] 83 c6 01 73}  //weight: 1, accuracy: Low
        $x_1_2 = "/8vlbYwQH2yHM9a3qxYMlIwfucPTFfbqBp2p8vdpNHW2ZUOA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

