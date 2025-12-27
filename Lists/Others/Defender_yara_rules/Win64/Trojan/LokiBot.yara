rule Trojan_Win64_LokiBot_RDH_2147845957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LokiBot.RDH!MTB"
        threat_id = "2147845957"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c9 48 8d 40 01 33 ca 69 d1 fb e3 ed 25 0f b6 08 84 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LokiBot_GVA_2147953888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LokiBot.GVA!MTB"
        threat_id = "2147953888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "The comment below contains SFX script commands" ascii //weight: 1
        $x_1_2 = "Setup=Ordine_01.pdf" ascii //weight: 1
        $x_1_3 = "Setup=\"Fattura_Berner_1483470414_del 30.09.2025.PDF" ascii //weight: 1
        $x_1_4 = {53 65 74 75 70 3d [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_2_5 = "Enter password for the encrypted file:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

