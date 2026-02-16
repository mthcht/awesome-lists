rule Trojan_Win64_CrysomeLoader_GVA_2147963127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CrysomeLoader.GVA!MTB"
        threat_id = "2147963127"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CrysomeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "91.92.242.133" ascii //weight: 5
        $x_5_2 = "130.94.115.151" ascii //weight: 5
        $x_2_3 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand" wide //weight: 2
        $x_1_4 = "schtasks /create /tn \"CrysomeLoader\" /tr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

