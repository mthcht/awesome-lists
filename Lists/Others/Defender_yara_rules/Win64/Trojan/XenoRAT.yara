rule Trojan_Win64_XenoRAT_A_2147919785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XenoRAT.A!MTB"
        threat_id = "2147919785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 7d ?? 48 63 04 24 48 8b 4c 24 20 0f b6 04 01 0f b6 4c 24 30 33 c1 48 63 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 2, accuracy: Low
        $x_4_2 = "aHR0cD" ascii //weight: 4
        $x_2_3 = "C:\\Users\\Public\\Downloads\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XenoRAT_GVA_2147975311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XenoRAT.GVA!MTB"
        threat_id = "2147975311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decompiler" ascii //weight: 1
        $x_1_2 = "XenoIcon.jpg" ascii //weight: 1
        $x_1_3 = "Xeno" ascii //weight: 1
        $x_1_4 = "create_directories" ascii //weight: 1
        $x_1_5 = "%LOCALAPPDATA%" wide //weight: 1
        $x_1_6 = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command" wide //weight: 1
        $x_1_7 = "[System.IO.Compression.ZipFile]::ExtractToDirectory" wide //weight: 1
        $x_1_8 = "-jar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XenoRAT_AA_2147977271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XenoRAT.AA!MTB"
        threat_id = "2147977271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {8b 4c 24 50 41 0f b6 44 11 e0 41 32 04 10 0f b6 c0 09 c8 89 44 24 50 48 83 c2}  //weight: 16, accuracy: High
        $x_4_2 = {4c 0f be 01 48 83 c1 ?? 4c 31 c0 49 0f af c1 48 39 d1 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

