rule Trojan_Win64_SideZusy_YAC_2147928258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SideZusy.YAC!MTB"
        threat_id = "2147928258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SideZusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c8 80 00 00 48 81 ec}  //weight: 1, accuracy: High
        $x_10_2 = {32 c3 48 8d 3f 48 8d 3f 02 c3 48 8d 3f 32 c3 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

