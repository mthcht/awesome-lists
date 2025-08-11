rule Trojan_Win64_IceTamper_A_2147949019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceTamper.A"
        threat_id = "2147949019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 6e 74 69 6e 65 6c 41 67 65 6e 74 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? 53 65 6e 74 69 6e 65 6c 53 65 72 76 69 63 65 48 6f 73 74 2e 65 78 65 ?? 53 65 6e 74 69 6e 65 6c 53 74 61 74 69 63 45 6e 67 69 6e 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? 53 65 6e 74 69 6e 65 6c 55 49 2e 65 78 65 ?? ?? 53 65 6e 74 69 6e 65 6c 48 65 6c 70 65 72 53 65 72 76 69 63 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? 4d 73 53 65 6e 73 65 2e 65 78 65 ?? ?? ?? ?? ?? 53 65 6e 73 65 54 56 4d 2e 65 78 65 ?? ?? ?? ?? 53 65 6e 73 65 4e 64 72 2e 65 78 65 ?? ?? ?? ?? 53 65 6e 73 65 49 52 2e 65 78 65 ?? ?? ?? ?? ?? 4d 73 4d 70 45 6e 67 2e 65 78 65 ?? ?? ?? ?? ?? 4d 70 44 65 66 65 6e 64 65 72 43 6f 72 65 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

