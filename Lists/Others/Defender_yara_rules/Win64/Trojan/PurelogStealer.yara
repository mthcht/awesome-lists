rule Trojan_Win64_PurelogStealer_AW_2147925939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PurelogStealer.AW!MTB"
        threat_id = "2147925939"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "focustask.exe" ascii //weight: 1
        $x_1_2 = "wextract.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PurelogStealer_HR_2147957985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PurelogStealer.HR!MTB"
        threat_id = "2147957985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 01 48 b8 0b d7 a3 70 3d 0a d7 a3 48 89 d6 48 f7 ea 48 8d 04 16 48 c1 f8 06 48 89 f2 48 c1 fe 3f 48 29 f0 48 6b c0 64 48 29 c2 48 89 51 08 48 b8 96 b2 0c 71 ac 8b db 68 48 f7 ef 48 c1 fa 0c 48 29 da 48 b8 0b d7 a3 70 3d 0a d7 a3 48 89 d3 48 f7 ea 48 8d 04 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

