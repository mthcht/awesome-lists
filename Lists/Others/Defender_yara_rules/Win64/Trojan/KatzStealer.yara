rule Trojan_Win64_KatzStealer_RH_2147942138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KatzStealer.RH!MTB"
        threat_id = "2147942138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KatzStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 45 00 00 64 86 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 02 2b 00 84 0d 00 00 e2 10 00 00 0e 00 00 20 13 00 00 00 10}  //weight: 3, accuracy: Low
        $x_1_2 = "Failed to set proxy blanket." ascii //weight: 1
        $x_1_3 = "Decryption failed. Last error:" ascii //weight: 1
        $x_1_4 = "\\Google\\Chrome\\User Data\\Local State" ascii //weight: 1
        $x_2_5 = "%s\\decrypted_appbound_key.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KatzStealer_GMX_2147957346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KatzStealer.GMX!MTB"
        threat_id = "2147957346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KatzStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 91 41 ff d4 49 91 4d 85 c9 ?? ?? 48 8b 05 ?? ?? ?? ?? 48 89 d9 45 31 c0 31 d2 48 89 74 24 ?? 48 89 44 24 ?? 48 83 64 24 ?? 00 83 64 24 ?? 00 ff d0}  //weight: 5, accuracy: Low
        $x_5_2 = {48 83 64 24 ?? 00 48 89 f2 48 89 d9 4c 8d 48 ?? 48 8b 05 ?? ?? ?? ?? 4c 8b 84 24 ?? ?? ?? ?? 48 89 44 24 ?? ff d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

