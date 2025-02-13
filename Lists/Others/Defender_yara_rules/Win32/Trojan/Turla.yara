rule Trojan_Win32_Turla_2147724874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Turla"
        threat_id = "2147724874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 45 d4 48 00 65 00 c7 45 d8 6c 00 70 00 c7 45 dc 41 00 73 00 c7 45 e0 73 00 69 00 c7 45 e4 73 00 74 00 c7 45 e8 61 00 6e 00 c7 45 ec 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Turla_Y_2147744633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Turla.Y!MSR"
        threat_id = "2147744633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://*:80/OWA/OAB/" ascii //weight: 1
        $x_1_2 = "https://*:443/OWA/OAB/" ascii //weight: 1
        $x_1_3 = "dcomnetsrv.cpp" wide //weight: 1
        $x_1_4 = "\\Develop\\sps\\neuron" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

