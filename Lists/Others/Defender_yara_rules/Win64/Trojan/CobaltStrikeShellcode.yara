rule Trojan_Win64_CobaltStrikeShellcode_CC_2147852375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeShellcode.CC!MTB"
        threat_id = "2147852375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeShellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e6 97 a0 e6 b3 95 e6 89 93 e5 bc 80 e9 85 8d e7 bd ae e6 96 87 e4 bb b6 e3 80 82 0a 00 e8 af bb e5 8f 96 53 68 65 6c 6c 63 6f 64 65}  //weight: 1, accuracy: High
        $x_1_2 = {b1 e8 b4 a5 e3 80 82 0a 00 e5 86 85 e5 ad 98 e5 88 86 e9 85 8d e5 a4 b1 e8 b4 a5 e3 80 82 0a}  //weight: 1, accuracy: High
        $x_1_3 = {e6 97 a0 e6 b3 95 e4 b8 ba 53 68 65 6c 6c 63 6f 64 65 e5 88 86 e9 85 8d e5 86 85 e5 ad 98 e3 80 82 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

