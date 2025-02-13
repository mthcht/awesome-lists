rule Trojan_MacOS_AmosAgent_PS_2147920905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosAgent.PS"
        threat_id = "2147920905"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "226465736b77616c6c6574732f456c65637472756d222c2070726f66696c65202620222f2e656c65637472756d2f77616c6c6574732f227d2" ascii //weight: 1
        $x_1_2 = "66696e642d67656e657269632d70617373776f7264202d6761205c224368726f6d655c22207c2061776b20" ascii //weight: 1
        $x_1_3 = "73797374656d5f70726f66696c6572205350536f667477617265446174615479706520535048617264776172654461746154797065" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

