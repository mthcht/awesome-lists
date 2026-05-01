rule Trojan_Win64_FrostTamper_A_2147968161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FrostTamper.A!dha"
        threat_id = "2147968161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FrostTamper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 61 76 6f 63 20 50 72 6f 63 65 73 ?? 20 54 65 72 6d 69 6e 61 74 6f 72}  //weight: 1, accuracy: Low
        $x_1_2 = {73 63 20 63 72 65 61 74 ?? 20 48 61 76 6f 63 20 62 69 6e 50 61 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {73 63 20 73 74 61 72 ?? 20 48 61 76 6f 63}  //weight: 1, accuracy: Low
        $x_1_4 = "HWAudioX64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

