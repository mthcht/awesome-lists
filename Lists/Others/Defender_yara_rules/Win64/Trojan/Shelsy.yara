rule Trojan_Win64_Shelsy_B_2147828177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelsy.B!MTB"
        threat_id = "2147828177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelsy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Users\\Administrator\\Downloads\\ProxineNewAuth\\x64\\Release\\Proxine.pdb" ascii //weight: 1
        $x_1_2 = {66 89 85 d4 02 00 00 c6 85 d0 02 00 00 4b 80 b5 d1 02 00 00 ?? 80 b5 d2 02 00 00 ?? 80 b5 d3 02 00 00 ?? 34 ?? 88 85 d4 02 00 00 80 b5 d5 02 00 00 ?? 48 8d 95 d0 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

