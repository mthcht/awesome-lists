rule Trojan_Win64_Arkmblk_VGZ_2147967349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Arkmblk.VGZ!MTB"
        threat_id = "2147967349"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Arkmblk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 c4 48 89 45 2f 33 c9 c6 45 b7 71 b2 02 88 4d ba 80 f2 71 b0 5c 88 55 b9 34 71 48 8d 55 b8 88 45 b8 49 8b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

