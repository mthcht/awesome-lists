rule Trojan_Win64_VaporRage_N_2147897445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VaporRage.N!dha"
        threat_id = "2147897445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VaporRage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {48 83 ec 28 ff ca 75 ?? b9 ?? 00 00 00 e8 ?? ?? ff ff 48 8d 0d ?? ?? ff ff 3d ?? ?? ?? ?? 74 e8 ?? ?? ff ff b8 01 00 00 00 48 83 c4 28 c3}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

