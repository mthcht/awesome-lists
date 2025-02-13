rule SoftwareBundler_Win32_Prepscram_226289_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram"
        threat_id = "226289"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 02 00 00 00 80 34 30 ?? 83 c0 03 3d ?? ?? ?? ?? 72 f2 8b 47 08 68 00 b0 00 00 ff 70 04 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Prepscram_226289_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram"
        threat_id = "226289"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_16_1 = {00 54 65 72 6d 69 6e 61 74 65 64 00}  //weight: 16, accuracy: High
        $x_16_2 = {00 31 32 30 00 2f 52 45 43 45 49 56 45 54 49 4d 45 4f 55 54 00 31 35 00 2f 43 4f 4e 4e 45 43 54 54 49 4d 45 4f 55 54 00 2f 4e 4f 43 41 4e 43 45 4c 00 2f 53 49 4c 45 4e 54 00 67 65 74 00}  //weight: 16, accuracy: High
        $x_1_3 = "://jump.milkcook.bid/" ascii //weight: 1
        $x_1_4 = "://flipit.bagamusement.bid/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_16_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_Prepscram_BM_257430_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram.BM!MTB"
        threat_id = "257430"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c b2 04 33 0c b2 23 cb 33 0c b2 8b c1 d1 e9 83 e0 01 69 c0 df b0 08 99 33 c1 33 84 b2 34 06 00 00 89 04 b2 46 81 fe e3 00 00 00 7c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c b2 04 33 0c b2 23 cb 33 0c b2 8b c1 d1 e9 83 e0 01 69 c0 df b0 08 99 33 c1 33 84 b2 74 fc ff ff 89 04 b2 46 81 fe 6f 02 00 00 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Prepscram_BN_258086_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram.BN!MTB"
        threat_id = "258086"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 45 ?? 8b 45 ?? 03 45 ?? 0f be 08 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 0f be 44 10 12 33 c8 8b 45 ?? 03 45 ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Prepscram_BA_259779_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram.BA!MTB"
        threat_id = "259779"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 20 89 7d c8 8a 0c 06 8b c6 f7 75 14 8b 45 08 88 4d 0f 8a 04 02 32 c1 8b 4d 18 88 04 0e 8b 45 bc 89 45 ec 8b 45 d4 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Prepscram_BB_260246_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram.BB!MTB"
        threat_id = "260246"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 8b c6 f7 75 ?? 8b 45 ?? 88 4d ?? 8a 04 02 32 c1 8b 4d ?? 88 04 0e 8b 45 ?? 89 45 ?? 8b 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b 45 ?? 89 75 ?? 8a 04 01 88 45 ?? 8b c1 f7 75 ?? 8b 45 ?? 8a 04 02 8b 55 ?? 32 45 ?? 88 04 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule SoftwareBundler_Win32_Prepscram_CA_261643_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram.CA!MTB"
        threat_id = "261643"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 75 14 33 d2 8b 75 c4 8b c6 f7 75 e0 8b 45 08 8a 0c 02 8b 45 20 8a 04 06 32 c1 8b 4d 18 88 04 0e 8b 45 b0 89 45 b8 8b 45 cc 89 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Prepscram_CB_261907_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Prepscram.CB!MTB"
        threat_id = "261907"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 89 7d ?? f7 75 ?? 8b 45 ?? 8a 0c 02 8b 45 ?? 8a 04 06 32 c1 8b 4d ?? 88 04 0e 8b 45 ?? 89 45 ?? 8b 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

