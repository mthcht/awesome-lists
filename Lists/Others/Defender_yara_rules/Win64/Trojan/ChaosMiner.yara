rule Trojan_Win64_ChaosMiner_A_2147962312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChaosMiner.A"
        threat_id = "2147962312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChaosMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "golang-cryptominer/Network/Client" ascii //weight: 1
        $x_1_2 = "http.socksUsernamePassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

