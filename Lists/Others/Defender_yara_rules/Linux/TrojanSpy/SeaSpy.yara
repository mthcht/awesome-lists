rule TrojanSpy_Linux_SeaSpy_A_2147849233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Linux/SeaSpy.A!MTB"
        threat_id = "2147849233"
        type = "TrojanSpy"
        platform = "Linux: Linux platform"
        family = "SeaSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "./BarracudaMailService <Network-Interface>" ascii //weight: 1
        $x_1_2 = "pcap_lookupnet" ascii //weight: 1
        $x_1_3 = "enter open tty shell" ascii //weight: 1
        $x_1_4 = "NO port code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

