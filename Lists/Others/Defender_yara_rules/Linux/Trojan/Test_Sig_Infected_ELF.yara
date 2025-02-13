rule Trojan_Linux_Test_Sig_Infected_ELF_2147910911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Test_Sig_Infected_ELF"
        threat_id = "2147910911"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Test_Sig_Infected_ELF"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f8f2f1ed-72ba-458e-8453-a1f9713b1195" ascii //weight: 1
        $x_1_2 = "71fc2884-95a2-4d77-8951-924d5c58d4f3" ascii //weight: 1
        $x_1_3 = "48dc8d29-0f61-49f3-b18c-1488ece8aef3" ascii //weight: 1
        $x_1_4 = "5d6f2919-0b2b-403f-976d-c061dcb4c634" ascii //weight: 1
        $x_1_5 = "1e81a0b5-df41-4cf5-b65a-704415470174" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

