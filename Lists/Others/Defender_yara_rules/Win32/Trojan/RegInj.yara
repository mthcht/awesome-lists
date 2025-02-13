rule Trojan_Win32_RegInj_J_2147752647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegInj.J!ibt"
        threat_id = "2147752647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegInj"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 04 00 00 04 74 05 00 00 01 28 0e 00 00 06 72 27 00 00 70 72 0e 01 00 70 72 58 01 00 70 28 0f 00 00 06 17 18 8d 02 00 00 01 0a 06 17 16 8d 02 00 00 01 a2 06 28 10 00 00 06 26}  //weight: 1, accuracy: High
        $x_1_2 = {7e 01 00 00 04 06 7e 01 00 00 04 06 91 7e 02 00 00 04 06 7e 03 00 00 04 5d 91 06 1b 58 7e 02 00 00 04 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_3 = "IaiyOxwJOTXzlrZDMTFe0EvkJx0Sc7QVI68qxnvoaiyOxwJOTXzlrZDMTFe0EvkJx0Sc7QVI68qxke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

