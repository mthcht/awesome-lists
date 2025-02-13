rule Trojan_Win32_JakyllHyde_SA_2147744264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JakyllHyde.SA!MSR"
        threat_id = "2147744264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JakyllHyde"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 65 64 67 90 01 03 2e 64 61 74}  //weight: 1, accuracy: High
        $x_3_2 = "e3e7e71a0b28b5e96cc492e636722f73" ascii //weight: 3
        $x_1_3 = {00 00 54 50 58 90 01 03 2e 64 61 74}  //weight: 1, accuracy: High
        $x_2_4 = "AdbFle.tmp" ascii //weight: 2
        $x_1_5 = "[BACKSPA[PAGE DO[CAPS LO[" wide //weight: 1
        $x_1_6 = "/drag0n/Specs/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_JakyllHyde_DEA_2147757865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JakyllHyde.DEA!MTB"
        threat_id = "2147757865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JakyllHyde"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//e3e7e71a0b28b5e96cc492e636722f73//4sVKAOvu3D//BDYot0NxyG.php" ascii //weight: 1
        $x_1_2 = "asssszzjddddddjjjzzxccssda" ascii //weight: 1
        $x_1_3 = "altered.twilightparadox.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

