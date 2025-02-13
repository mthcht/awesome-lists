rule Trojan_Win64_Latot_A_2147890069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latot.A!MTB"
        threat_id = "2147890069"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 0b 48 ff c3 88 4c 1a ff 84 c9}  //weight: 2, accuracy: High
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

