rule Trojan_Win32_Latrodectus_C_2147919790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Latrodectus.C!MTB"
        threat_id = "2147919790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 d8 41 8b c0 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea 41 8b c0 d1 fa 8b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Latrodectus_A_2147931460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Latrodectus.A"
        threat_id = "2147931460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 06 6a 90}  //weight: 1, accuracy: High
        $x_1_2 = {87 b8 c9 d4}  //weight: 1, accuracy: High
        $x_1_3 = {f6 b1 00 ff}  //weight: 1, accuracy: High
        $x_1_4 = {69 00 0d 66 19 00}  //weight: 1, accuracy: High
        $x_1_5 = {c7 04 24 c5 9d 1c 81}  //weight: 1, accuracy: High
        $x_1_6 = {69 04 24 93 01 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

