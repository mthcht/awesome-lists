rule Trojan_Win64_WoolenGoldfish_LK_2147844208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WoolenGoldfish.LK!MTB"
        threat_id = "2147844208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WoolenGoldfish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b a3 00 00 00 00 41 52 4d 89 da 4d 21 e2 4d 01 d2 4d 01 dc 4d 29 d4 41 5a 4c 89 a3 00 00 00 00 [0-255] e9}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\wrappers\\agent_wrapper\\wrapper_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

