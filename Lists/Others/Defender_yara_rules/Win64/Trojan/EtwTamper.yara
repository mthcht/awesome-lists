rule Trojan_Win64_EtwTamper_GVA_2147971675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EtwTamper.GVA!MTB"
        threat_id = "2147971675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EtwTamper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ad ab ff c9 75 fa}  //weight: 1, accuracy: High
        $x_1_2 = {ac aa ff ca 75 fa}  //weight: 1, accuracy: High
        $x_1_3 = {44 30 14 08 44 02 14 08 e2 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

