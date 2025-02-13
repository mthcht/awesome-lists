rule Trojan_Win64_GadgetBoy_B_2147811735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GadgetBoy.B!dha"
        threat_id = "2147811735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GadgetBoy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {73 74 61 74 65 2e 64 6c 6c 00 4d 6f 6e 69 74 6f 72 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 4, accuracy: High
        $x_2_2 = "Global//CCAPP%d" ascii //weight: 2
        $x_1_3 = "DmptfXjoepxTubujpo" ascii //weight: 1
        $x_1_4 = "Qspdftt43Ofyu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

