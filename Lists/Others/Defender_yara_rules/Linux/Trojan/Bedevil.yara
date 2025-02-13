rule Trojan_Linux_Bedevil_A_2147766647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Bedevil.A!MTB"
        threat_id = "2147766647"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Bedevil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ICMP backdoor up" ascii //weight: 1
        $x_1_2 = "Accept backdoor port" ascii //weight: 1
        $x_3_3 = {55 89 e5 56 53 81 ec 50 01 00 00 e8 31 7b ff ff 81 c3 d1 cf 00 00 e8 d6 73 ff ff 85 c0 75 09 e8 8d 75 ff ff 85 c0 74 05 e9 85 02 00 00 8d 83 90 b4 ff ff 89 04 24 e8 26 6d ff ff e8 11 77 ff ff 89 45 f0 83 7d f0 00 74 05 e9 64 02 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Bedevil_B_2147771924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Bedevil.B!MTB"
        threat_id = "2147771924"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Bedevil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chkrootkit" ascii //weight: 1
        $x_1_2 = "ICMP backdoor up" ascii //weight: 1
        $x_1_3 = "./bdvprep" ascii //weight: 1
        $x_1_4 = "bin/statiyicrhge/hide_ports" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_Bedevil_C_2147899464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Bedevil.C!MTB"
        threat_id = "2147899464"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Bedevil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsrootkit" ascii //weight: 1
        $x_1_2 = "writebashrc" ascii //weight: 1
        $x_1_3 = "bdvprep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

