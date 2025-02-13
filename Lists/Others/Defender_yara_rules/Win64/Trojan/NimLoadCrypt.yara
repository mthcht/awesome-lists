rule Trojan_Win64_NimLoadCrypt_LK_2147846055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NimLoadCrypt.LK!MTB"
        threat_id = "2147846055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NimLoadCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d8 48 89 d9 48 c1 f8 ?? 48 c1 f9 10 31 d8 31 c8 48 89 d9 48 c1 f9 ?? 31 c8 30 44 ?? ?? 48 83 c3 01 4c 39 c3 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

