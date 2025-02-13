rule Trojan_Win64_SpyLoader_MFP_2147834887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyLoader.MFP!MTB"
        threat_id = "2147834887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 8b 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 49 89 ca 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SpyLoader_SL_2147841759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyLoader.SL!MTB"
        threat_id = "2147841759"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 f9 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 01 d6 6b d6 ?? 29 d7 48 ?? ?? 42 ?? ?? ?? 32 14 0b 88 14 08 48 ?? ?? 8b 95 ?? ?? ?? ?? 48 ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SpyLoader_SA_2147889461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyLoader.SA!MTB"
        threat_id = "2147889461"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 04 01 41 ff c0 ff ca 30 01 48 ff c1 49 ff c1 44 3b 05 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 07 32 01 48 ff c1 88 04 3a 48 ff c7 80 39 ?? 48 0f 44 cd 80 3f ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SpyLoader_NS_2147898389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyLoader.NS!MTB"
        threat_id = "2147898389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aimbot visible" ascii //weight: 1
        $x_1_2 = "config.dat" ascii //weight: 1
        $x_1_3 = "Show Fov" ascii //weight: 1
        $x_1_4 = "aimbot" ascii //weight: 1
        $x_1_5 = "APEX.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

