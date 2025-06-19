rule Trojan_Win64_Bodegun_ABD_2147939881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bodegun.ABD!MTB"
        threat_id = "2147939881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f1 55 48 8d 7f 01 49 3b d0 73 ?? 48 8d 42 01 48 89 45 bf 48 8d 45 af 49 83 f8 0f 48 0f 47 45 af 88 0c 10 c6 44 10 01 00 eb 0d 44 0f b6 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bodegun_KK_2147944059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bodegun.KK!MTB"
        threat_id = "2147944059"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 2b c6 41 8b c0 c1 e8 18 32 c1 88 85 ?? ?? 00 00 41 8b c0 c1 e8 10 32 c1 88 85 ?? ?? 00 00 41 8b c0 c1 e8 08 32 c1 88 85 [0-20] 00 00 33 c0 0f 57 c9 f3 0f 7f 8d ?? 02 00 00 48 89 85 ?? 02 00 00 88 4c 24 ?? 4c 8d 44 24 ?? 33 d2 48 8d 8d ?? 02 00 00}  //weight: 5, accuracy: Low
        $x_25_2 = {52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 [0-8] 52 61 6e 73 6f 6d 77 61 72 65 [0-8] 2e 70 64 62}  //weight: 25, accuracy: Low
        $x_5_3 = "Added to Registry RunOnce (will run at next logon)." ascii //weight: 5
        $x_5_4 = "Failed to add to Startup Folder via WScript.Shell method." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_25_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

