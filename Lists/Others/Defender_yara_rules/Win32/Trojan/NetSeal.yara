rule Trojan_Win32_NetSeal_A_2147740584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetSeal.A!ibt"
        threat_id = "2147740584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetSeal"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://seal.elitevs.net/Base" wide //weight: 1
        $x_1_2 = "http://seal.nimoru.com/Base/" wide //weight: 1
        $x_1_3 = "BgIAAAAiAABEU1MxAAQAAKVlurdZMaHy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

