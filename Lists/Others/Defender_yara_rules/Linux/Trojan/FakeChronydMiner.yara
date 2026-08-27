rule Trojan_Linux_FakeChronydMiner_A_2147977112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FakeChronydMiner.A"
        threat_id = "2147977112"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FakeChronydMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/etc/systemd/system/chronyd-helper.service" ascii //weight: 5
        $x_3_2 = "/usr/sbin/_chronyd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

