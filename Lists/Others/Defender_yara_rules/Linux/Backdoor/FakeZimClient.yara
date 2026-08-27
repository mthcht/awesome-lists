rule Backdoor_Linux_FakeZimClient_A_2147977114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/FakeZimClient.A"
        threat_id = "2147977114"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "FakeZimClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ws://psk1zim.abrdns.com:80/agentws" ascii //weight: 3
        $x_3_2 = "tls.psk1zim.abrdns.com" ascii //weight: 3
        $x_3_3 = "ws://gittest.work.gd:80/agentws" ascii //weight: 3
        $x_3_4 = "tls://gittest.work.gd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

