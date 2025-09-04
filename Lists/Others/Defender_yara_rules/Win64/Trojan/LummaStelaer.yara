rule Trojan_Win64_LummaStelaer_MR_2147951459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStelaer.MR!MTB"
        threat_id = "2147951459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStelaer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 ?? ?? ?? c0 05 00 00 02}  //weight: 5, accuracy: Low
        $x_5_2 = {40 00 00 e0 2e 72 73 72 63 ?? ?? ?? c0 02 ?? ?? ?? b0 05 00 00 02 ?? ?? ?? b0 05}  //weight: 5, accuracy: Low
        $x_5_3 = {20 20 20 00 20 20 20 20 00 a0 05 00 00 10 ?? ?? ?? a0 05 00 00 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

