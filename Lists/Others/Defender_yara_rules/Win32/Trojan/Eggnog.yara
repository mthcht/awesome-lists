rule Trojan_Win32_Eggnog_MA_2147836279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eggnog.MA!MTB"
        threat_id = "2147836279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eggnog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c3 60 61 6a 0a 5f 99 f7 ff 80 c2 30 29 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 50 5b 49 09 db 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eggnog_EM_2147851718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eggnog.EM!MTB"
        threat_id = "2147851718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eggnog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Xolox" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\LimeWire" ascii //weight: 1
        $x_1_3 = "Software\\Morpheus" ascii //weight: 1
        $x_1_4 = "C:\\My Downloads" ascii //weight: 1
        $x_1_5 = "Worm.P2P.Google" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

