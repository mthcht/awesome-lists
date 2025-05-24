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

