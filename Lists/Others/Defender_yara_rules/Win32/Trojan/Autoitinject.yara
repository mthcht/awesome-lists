rule Trojan_Win32_Autoitinject_SS_2147789479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SS!MTB"
        threat_id = "2147789479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l\" )" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l\" & \"A\" & \"d\" & \"d\" & \"r\" & \"e\" & \"s\" & \"s\" )" ascii //weight: 1
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 53 00 45 00 54 00 44 00 41 00 54 00 41 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {44 4c 4c 53 54 52 55 43 54 53 45 54 44 41 54 41 20 28 20 24 [0-20] 20 2c 20 31 20 2c 20 24 [0-20] 20 29}  //weight: 2, accuracy: Low
        $x_1_7 = "REGDELETE ( \"default\" , \"Pd\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PQH_2147920847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PQH!MTB"
        threat_id = "2147920847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "k99DD04AAe99DD04AAr99DD04AAn99DD04AAe99DD04AAl99DD04AA399DD04AA299DD04AA" ascii //weight: 5
        $x_7_5 = "b99DD04AAy99DD04AAt99DD04AAe99DD04AA" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PSH_2147920916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PSH!MTB"
        threat_id = "2147920916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "30A022k30A022e30A022r30A022n30A022e30A022l30A022330A022230A022" ascii //weight: 5
        $x_7_5 = "30A022u30A022s30A022e30A022r30A022330A022230A022" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPH_2147921867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPH!MTB"
        threat_id = "2147921867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k950015789e950015789r950015789n950015789e950015789l95001578939500157892950015789" ascii //weight: 5
        $x_7_4 = "u950015789s950015789e950015789r95001578939500157892950015789" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPCH_2147921869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPCH!MTB"
        threat_id = "2147921869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k2qtc53dse2qtc53dsr2qtc53dsn2qtc53dse2qtc53dsl2qtc53ds32qtc53ds22qtc53ds" ascii //weight: 5
        $x_7_4 = "u2qtc53dss2qtc53dse2qtc53dsr2qtc53ds32qtc53ds22qtc53ds" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPEH_2147921871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPEH!MTB"
        threat_id = "2147921871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k5s0ftwm6e5s0ftwm6r5s0ftwm6n5s0ftwm6e5s0ftwm6l5s0ftwm635s0ftwm625s0ftwm6" ascii //weight: 5
        $x_7_4 = "u5s0ftwm6s5s0ftwm6e5s0ftwm6r5s0ftwm635s0ftwm625s0ftwm6" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPFH_2147921872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPFH!MTB"
        threat_id = "2147921872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k7IfgcdZxe7IfgcdZxr7IfgcdZxn7IfgcdZxe7IfgcdZxl7IfgcdZx37IfgcdZx27IfgcdZx" ascii //weight: 5
        $x_7_4 = "u7IfgcdZxs7IfgcdZxe7IfgcdZxr7IfgcdZx37IfgcdZx27IfgcdZx" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PHIH_2147921874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PHIH!MTB"
        threat_id = "2147921874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k0qk5dd92e0qk5dd92r0qk5dd92n0qk5dd92e0qk5dd92l0qk5dd9230qk5dd9220qk5dd92" ascii //weight: 5
        $x_7_4 = "u0qk5dd92s0qk5dd92e0qk5dd92r0qk5dd9230qk5dd9220qk5dd92" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SPIH_2147922126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPIH!MTB"
        threat_id = "2147922126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k6wcRq90de6wcRq90dr6wcRq90dn6wcRq90de6wcRq90dl6wcRq90d36wcRq90d26wcRq90d.6wcRq90dd6wcRq90dl6wcRq90dl6wcRq90d" ascii //weight: 5
        $x_3_4 = "u6wcRq90ds6wcRq90de6wcRq90dr6wcRq90d36wcRq90d26wcRq90d.6wcRq90dd6wcRq90dl6wcRq90dl6wcRq90d" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PHOH_2147922345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PHOH!MTB"
        threat_id = "2147922345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k8tqp05tss9e8tqp05tss9r8tqp05tss9n8tqp05tss9e8tqp05tss9l8tqp05tss938tqp05tss928tqp05tss9" ascii //weight: 5
        $x_7_4 = "u8tqp05tss9s8tqp05tss9e8tqp05tss9r8tqp05tss938tqp05tss928tqp05tss9" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PPQH_2147922513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PPQH!MTB"
        threat_id = "2147922513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k2sYcsae2sYcsar2sYcsan2sYcsae2sYcsal2sYcsa32sYcsa22sYcsa" ascii //weight: 5
        $x_7_4 = "u2sYcsas2sYcsae2sYcsar2sYcsa32sYcsa22sYcsa" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PHHA_2147923118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PHHA!MTB"
        threat_id = "2147923118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = "kNBeRIrBVnWSeQMlJH3TO2DY" ascii //weight: 5
        $x_7_4 = "VNBiRIrBVtWSuQMaJHlTOADYlTAlFEoMBcST" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PIIH_2147923709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PIIH!MTB"
        threat_id = "2147923709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = "kIS5XeIS5XrIS5XnIS5XeIS5XlIS5X3IS5X2IS5X" ascii //weight: 5
        $x_7_4 = "VIS5XiIS5XrIS5XtIS5XuIS5XaIS5XlIS5XPIS5XrIS5XoIS5XtIS5XeIS5XcIS5XtIS5X" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SPGH_2147924125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPGH!MTB"
        threat_id = "2147924125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "k2du3we2du3wr2du3wn2du3we2du3wl2du3w32du3w22du3w.2du3wd2du3wl2du3wl2du3w" ascii //weight: 5
        $x_3_2 = "u2du3ws2du3we2du3wr2du3w32du3w22du3w.2du3wd2du3wl2du3wl2du3w" ascii //weight: 3
        $x_1_3 = "\"D\" & \"ll\" & \"C\" & \"all" ascii //weight: 1
        $x_1_4 = "@Te\" & \"mpDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SPHJ_2147924214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPHJ!MTB"
        threat_id = "2147924214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "u8zgbxs8zgbxe8zgbxr8zgbx38zgbx28zgbx.8zgbxd8zgbxl8zgbxl8zgbx" ascii //weight: 5
        $x_3_2 = "k8zgbxe8zgbxr8zgbxn8zgbxe8zgbxl8zgbx38zgbx28zgbx.8zgbxd8zgbxl8zgbxl8zgbx" ascii //weight: 3
        $x_1_3 = "DllCall" ascii //weight: 1
        $x_1_4 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PNHH_2147924470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PNHH!MTB"
        threat_id = "2147924470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6c 00 66 00 73 00 6f 00 66 00 6d 00 34 00 33 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 71 00 75 00 73 00 22 00 22 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {22 44 6c 22 20 26 20 22 6c 43 61 6c 6c 28 [0-20] 28 22 22 6c 66 73 6f 66 6d 34 33 22 22 29 2c 20 00 28 22 22 71 75 73 22 22 29}  //weight: 2, accuracy: Low
        $x_2_3 = {22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 22 00 20 00 26 00 20 00 22 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-20] 28 00 22 00 22 00 63 00 7a 00 75 00 66 00 21 00 5c 00 22 00 22 00 29 00 20 00 26 00 20 00 42 00 69 00 6e 00 61 00 72 00 22 00 20 00 26 00 20 00 22 00 79 00 4c 00 65 00 6e 00}  //weight: 2, accuracy: Low
        $x_2_4 = {22 44 6c 6c 53 74 72 75 63 22 20 26 20 22 74 43 72 65 61 74 65 28 [0-20] 28 22 22 63 7a 75 66 21 5c 22 22 29 20 26 20 42 69 6e 61 72 22 20 26 20 22 79 4c 65 6e}  //weight: 2, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2d 00 20 00 28 00 20 00 31 00 20 00 5e 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 43 48 52 20 28 20 24 [0-20] 20 2d 20 28 20 31 20 5e 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PNPH_2147924760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PNPH!MTB"
        threat_id = "2147924760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "@Tem\" & \"pDir" ascii //weight: 2
        $x_2_2 = {22 00 44 00 6c 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 70 00 77 00 71 00 6f 00 65 00 70 00 77 00 71 00 6f 00 72 00 70 00 77 00 71 00 6f 00 6e 00 70 00 77 00 71 00 6f 00 65 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 33 00 70 00 77 00 71 00 6f 00 32 00 70 00 77 00 71 00 6f 00 2e 00 70 00 77 00 71 00 6f 00 64 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 22 00 22 00 29 00}  //weight: 2, accuracy: Low
        $x_2_3 = {22 44 6c 6c 22 20 26 20 22 43 61 6c 6c 28 [0-20] 28 22 22 6b 70 77 71 6f 65 70 77 71 6f 72 70 77 71 6f 6e 70 77 71 6f 65 70 77 71 6f 6c 70 77 71 6f 33 70 77 71 6f 32 70 77 71 6f 2e 70 77 71 6f 64 70 77 71 6f 6c 70 77 71 6f 6c 70 77 71 6f 22 22 29}  //weight: 2, accuracy: Low
        $x_1_4 = {22 00 44 00 6c 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 75 00 70 00 77 00 71 00 6f 00 73 00 70 00 77 00 71 00 6f 00 65 00 70 00 77 00 71 00 6f 00 72 00 70 00 77 00 71 00 6f 00 33 00 70 00 77 00 71 00 6f 00 32 00 70 00 77 00 71 00 6f 00 2e 00 70 00 77 00 71 00 6f 00 64 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 6c 00 70 00 77 00 71 00 6f 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {22 44 6c 6c 22 20 26 20 22 43 61 6c 6c 28 [0-20] 28 22 22 75 70 77 71 6f 73 70 77 71 6f 65 70 77 71 6f 72 70 77 71 6f 33 70 77 71 6f 32 70 77 71 6f 2e 70 77 71 6f 64 70 77 71 6f 6c 70 77 71 6f 6c 70 77 71 6f 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PNQH_2147924867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PNQH!MTB"
        threat_id = "2147924867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 65 00 6b 00 6c 00 74 00 5f 00 72 00 2d 00 38 00 22 00 22 00 2c 00 20 00 36 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 6a 00 7a 00 6c 00 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 65 6b 6c 74 5f 72 2d 38 22 22 2c 20 36 29 2c 20 [0-20] 28 22 22 6a 7a 6c 22 22 2c 20 36 29}  //weight: 2, accuracy: Low
        $x_2_3 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6f 00 79 00 5f 00 78 00 2d 00 38 00 22 00 22 00 2c 00 20 00 36 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 66 00 78 00 5f 00 79 00 6f 00 72 00 6e 00 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 6f 79 5f 78 2d 38 22 22 2c 20 36 29 2c 20 [0-20] 28 22 22 66 78 5f 79 6f 72 6e 22 22 2c 20 36 29}  //weight: 2, accuracy: Low
        $x_1_5 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 65 00 6b 00 6c 00 74 00 5f 00 72 00 2d 00 38 00 22 00 22 00 2c 00 20 00 36 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 5e 00 7d 00 69 00 78 00 5e 00 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 65 6b 6c 74 5f 72 2d 38 22 22 2c 20 36 29 2c 20 [0-20] 28 22 22 5e 7d 69 78 5e 22 22 2c 20 36 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SZPJ_2147925513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SZPJ!MTB"
        threat_id = "2147925513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "k550060e550060r550060n550060e550060l55006035500602550060.550060d550060l550060l550060" ascii //weight: 4
        $x_3_2 = "u550060s550060e550060r55006035500602550060.550060d550060l550060l550060" ascii //weight: 3
        $x_1_3 = "DllCall" ascii //weight: 1
        $x_1_4 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PMFH_2147925742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PMFH!MTB"
        threat_id = "2147925742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "k52110e52110r52110n52110e52110l52110352110252110" ascii //weight: 5
        $x_7_4 = "u52110s52110e52110r52110352110252110" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PMNH_2147925926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PMNH!MTB"
        threat_id = "2147925926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_5_3 = "52110k52110e52110r52110n52110e52110l52110352110252110" ascii //weight: 5
        $x_7_4 = "52110V52110i52110r52110t52110u52110a52110l52110P52110r52110o52110t52110e52110c52110t52110" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_PMSH_2147926140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PMSH!MTB"
        threat_id = "2147926140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 00 44 00 6c 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 65 00 72 00 22 00 22 00 20 00 26 00 20 00 22 00 22 00 6e 00 65 00 6c 00 33 00 22 00 22 00 20 00 26 00 20 00 22 00 22 00 32 00 37 00 54 00 63 00 41 00 67 00 57 00 50 00 6b 00 22 00 22 00 20 00 26 00 20 00 22 00 22 00 [0-20] 22 00 22 00 2c 00 20 00 38 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {22 44 6c 6c 43 22 20 26 20 22 61 6c 6c 28 [0-20] 28 22 22 6b 65 72 22 22 20 26 20 22 22 6e 65 6c 33 22 22 20 26 20 22 22 32 37 54 63 41 67 57 50 6b 22 22 20 26 20 22 22 [0-20] 22 22 2c 20 38 29}  //weight: 2, accuracy: Low
        $x_2_3 = {22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 22 00 20 00 26 00 20 00 22 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-20] 28 00 22 00 22 00 62 00 22 00 22 00 20 00 26 00 20 00 22 00 22 00 79 00 74 00 65 00 20 00 5b 00 37 00 54 00 63 00 41 00 22 00 20 00 26 00 20 00 22 00 67 00 57 00 50 00 6b 00 22 00 22 00 20 00 26 00 20 00 22 00 22 00 [0-20] 22 00 22 00 2c 00 20 00 36 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {22 44 6c 6c 53 74 72 75 63 22 20 26 20 22 74 43 72 65 61 74 65 28 [0-20] 28 22 22 62 22 22 20 26 20 22 22 79 74 65 20 5b 37 54 63 41 22 20 26 20 22 67 57 50 6b 22 22 20 26 20 22 22 [0-20] 22 22 2c 20 36 29}  //weight: 2, accuracy: Low
        $x_1_5 = {22 00 44 00 6c 00 6c 00 53 00 22 00 20 00 26 00 20 00 22 00 74 00 72 00 75 00 22 00 20 00 26 00 20 00 22 00 63 00 74 00 53 00 65 00 22 00 20 00 26 00 20 00 22 00 74 00 44 00 61 00 74 00 22 00 20 00 26 00 20 00 22 00 61 00 28 00 24 00 [0-20] 22 00 20 00 26 00 20 00 22 00 2c 00 20 00 31 00 2c 00 20 00 22 00 20 00 26 00 20 00 22 00 24 00 [0-20] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {22 44 6c 6c 53 22 20 26 20 22 74 72 75 22 20 26 20 22 63 74 53 65 22 20 26 20 22 74 44 61 74 22 20 26 20 22 61 28 24 [0-20] 22 20 26 20 22 2c 20 31 2c 20 22 20 26 20 22 24 [0-20] 29 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PLNH_2147929409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PLNH!MTB"
        threat_id = "2147929409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_2_4 = {22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 33 00 65 00 72 00 6b 00 32 00 6c 00 6e 00 65 00 22 00 22 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 72 00 70 00 74 00 22 00 22 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 6f 00 6c 00 6c 00 75 00 72 00 56 00 63 00 6c 00 41 00 61 00 74 00 69 00 22 00 22 00 29 00}  //weight: 2, accuracy: Low
        $x_2_5 = {22 44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 33 65 72 6b 32 6c 6e 65 22 22 29 2c 20 [0-20] 28 22 22 72 70 74 22 22 29 2c 20 [0-20] 28 22 22 6f 6c 6c 75 72 56 63 6c 41 61 74 69 22 22 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_PLLAH_2147929795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.PLLAH!MTB"
        threat_id = "2147929795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-15] 20 00 28 00 20 00 22 00 48 00 7c 00 6a 00 69 00 7c 00 7c 00 6e 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-15] 20 00 26 00 20 00 22 00 28 00 [0-15] 28 00 22 00 22 00 6e 00 69 00 77 00 74 00 6c 00 74 00 3c 00 3c 00 39 00 70 00 79 00 7a 00 22 00 22 00 2c 00 20 00 32 00 29 00 2c 00 20 00 02 28 00 22 00 22 00 65 00 73 00 74 00 72 00 22 00 22 00 2c 00 20 00 32 00 29 00 2c 00 20 00 02 28 00 22 00 22 00 59 00 6d 00 77 00 7a 00 7c 00 69 00 75 00 5a 00}  //weight: 4, accuracy: Low
        $x_4_2 = {43 41 4c 4c 20 28 20 [0-15] 20 28 20 22 48 7c 6a 69 7c 7c 6e 22 20 2c 20 32 20 29 20 2c 20 24 [0-15] 20 26 20 22 28 [0-15] 28 22 22 6e 69 77 74 6c 74 3c 3c 39 70 79 7a 22 22 2c 20 32 29 2c 20 02 28 22 22 65 73 74 72 22 22 2c 20 32 29 2c 20 02 28 22 22 59 6d 77 7a 7c 69 75 5a}  //weight: 4, accuracy: Low
        $x_1_3 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-15] 20 00 28 00 20 00 22 00 48 00 7c 00 6a 00 69 00 7c 00 7c 00 6e 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-15] 20 00 26 00 20 00 22 00 28 00 [0-15] 28 00 22 00 22 00 78 00 77 00 6a 00 78 00 3a 00 3a 00 37 00 6e 00 77 00 78 00 22 00 22 00 2c 00 20 00 32 00 29 00 2c 00 20 00 02 28 00 22 00 22 00 73 00 78 00 77 00 22 00 22 00 2c 00 20 00 32 00 29 00 2c 00 20 00 02 28 00 22 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 41 4c 4c 20 28 20 [0-15] 20 28 20 22 48 7c 6a 69 7c 7c 6e 22 20 2c 20 32 20 29 20 2c 20 24 [0-15] 20 26 20 22 28 [0-15] 28 22 22 78 77 6a 78 3a 3a 37 6e 77 78 22 22 2c 20 32 29 2c 20 02 28 22 22 73 78 77 22 22 2c 20 32 29 2c 20 02 28 22 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SPNH_2147933107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPNH!MTB"
        threat_id = "2147933107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE" ascii //weight: 1
        $x_4_2 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 38 00 7b 00 31 00 30 00 32 00 7b 00 31 00 31 00 35 00 7b 00 31 00 31 00 31 00 7b 00 31 00 30 00 32 00 7b 00 31 00 30 00 39 00 7b 00 35 00 32 00 7b 00 35 00 31 00 7b 00 34 00 37 00 7b 00 31 00 30 00 31 00 7b 00 31 00 30 00 39 00 7b 00 31 00 30 00 39 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 31 00 30 00 31 00 7b 00 31 00 32 00 30 00 7b 00 31 00 31 00 32 00 7b 00 31 00 31 00 35 00 7b 00 31 00 30 00 31 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00}  //weight: 4, accuracy: Low
        $x_4_3 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-20] 20 28 20 22 31 30 38 7b 31 30 32 7b 31 31 35 7b 31 31 31 7b 31 30 32 7b 31 30 39 7b 35 32 7b 35 31 7b 34 37 7b 31 30 31 7b 31 30 39 7b 31 30 39 22 20 2c 20 31 20 29 20 2c 20 00 20 28 20 22 31 30 31 7b 31 32 30 7b 31 31 32 7b 31 31 35 7b 31 30 31 22 20 2c 20 31 20 29 20 2c 20 00 20 28 20 22}  //weight: 4, accuracy: Low
        $x_1_4 = "\"69{110{113{117{103{74{99{112{102{110{103\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SPDH_2147933134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPDH!MTB"
        threat_id = "2147933134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "k281250650er281250650nel32812506502" ascii //weight: 5
        $x_7_5 = "281250650V281250650ir281250650tualA281250650llo281250650c" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SCMH_2147933264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SCMH!MTB"
        threat_id = "2147933264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "k94584120er94584120nel3945841202" ascii //weight: 5
        $x_6_5 = "94584120V94584120ir94584120tualA94584120llo94584120c" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SCCH_2147933308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SCCH!MTB"
        threat_id = "2147933308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "\"Dl\" & \"lC\" & \"all\"" ascii //weight: 1
        $x_5_4 = "k94584120er94584120nel3945841202" ascii //weight: 5
        $x_6_5 = "94584120V94584120ir94584120tualA94584120llo94584120c" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autoitinject_SXCU_2147933447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SXCU!MTB"
        threat_id = "2147933447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 24 00 [0-20] 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 24 [0-20] 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_6_5 = {28 00 20 00 22 00 78 00 76 00 61 00 7d 00 76 00 [0-10] 22 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 63 00 67 00 61 00 22 00 20 00 29 00 20 00 2c 00 20 00 01 20 00 28 00 20 00 22 00 45 00 7a 00 61 00 67 00 66 00 72 00 [0-20] 22 00 20 00 29 00 20 00 2c 00 20 00 01 20 00 28 00 20 00 22 00 77 00 64 00 7c 00 61 00 77 00 22 00 20 00 29 00}  //weight: 6, accuracy: Low
        $x_6_6 = {28 20 22 78 76 61 7d 76 [0-10] 22 20 29 20 2c 20 [0-20] 20 28 20 22 63 67 61 22 20 29 20 2c 20 01 20 28 20 22 45 7a 61 67 66 72 [0-20] 22 20 29 20 2c 20 01 20 28 20 22 77 64 7c 61 77 22 20 29}  //weight: 6, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 51 00 7a 00 7d 00 72 00 61 00 6a 00 5f 00 76 00 7d 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 51 7a 7d 72 61 6a 5f 76 7d 22 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SCHZ_2147933795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SCHZ!MTB"
        threat_id = "2147933795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = {26 00 3d 00 20 00 24 00 [0-20] 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_4 = {26 3d 20 24 [0-20] 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-20] 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 5, accuracy: Low
        $x_6_5 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 50 00 78 00 78 00 57 00 75 00 78 00 78 00 22 00 20 00 29 00 20 00 29 00}  //weight: 6, accuracy: Low
        $x_6_6 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 50 78 78 57 75 78 78 22 20 29 20 29}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*))) or
            ((2 of ($x_6_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SHZD_2147935417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SHZD!MTB"
        threat_id = "2147935417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 78 00 72 00 65 00 33 00 35 00 38 00 30 00 32 00 35 00 32 00 35 00 61 00 72 00 79 00 33 00 35 00 38 00 30 00 32 00 35 00 32 00 35 00 33 00 32 00 22 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 63 00 67 00 33 00 35 00 38 00 30 00 32 00 35 00 32 00 35 00 65 00 22 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-30] 20 28 20 22 78 72 65 33 35 38 30 32 35 32 35 61 72 79 33 35 38 30 32 35 32 35 33 32 22 20 29 20 2c 20 00 20 28 20 22 63 67 33 35 38 30 32 35 32 35 65 22 20 29 20 2c 20 00 20 28 20 22}  //weight: 2, accuracy: Low
        $x_1_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 22 00 20 00 26 00 20 00 22 00 69 00 6e 00 67 00 52 00 65 00 70 00 6c 00 22 00 20 00 26 00 20 00 22 00 61 00 63 00 65 00 28 00 24 00 [0-30] 2c 00 20 00 22 00 22 00 33 00 35 00 38 00 30 00 32 00 35 00 32 00 35 00 22 00 22 00 2c 00 20 00 22 00 22 00 22 00 22 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 58 45 43 55 54 45 20 28 20 22 53 74 72 22 20 26 20 22 69 6e 67 52 65 70 6c 22 20 26 20 22 61 63 65 28 24 [0-30] 2c 20 22 22 33 35 38 30 32 35 32 35 22 22 2c 20 22 22 22 22 29 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SOZD_2147936937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SOZD!MTB"
        threat_id = "2147936937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 22 00 20 00 26 00 20 00 22 00 28 00 22 00 20 00 26 00 20 00 22 00 42 00 22 00 20 00 26 00 20 00 22 00 69 00 22 00 20 00 26 00 20 00 22 00 74 00 22 00 20 00 26 00 20 00 22 00 58 00 22 00 20 00 26 00 20 00 22 00 4f 00 22 00 20 00 26 00 20 00 22 00 52 00 22 00 20 00 26 00 20 00 22 00 28 00 22 00 20 00 26 00 20 00 22 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 22 00 20 00 26 00 20 00 22 00 28 00 22 00 20 00 26 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 22 00 20 00 26 00 20 00 22 00 28 00 24 00 [0-20] 29 00 29 00 2c 00 20 00 24 00 [0-20] 29 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 22 20 26 20 22 28 22 20 26 20 22 42 22 20 26 20 22 69 22 20 26 20 22 74 22 20 26 20 22 58 22 20 26 20 22 4f 22 20 26 20 22 52 22 20 26 20 22 28 22 20 26 20 22 41 22 20 26 20 22 73 22 20 26 20 22 63 22 20 26 20 22 28 22 20 26 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 22 20 26 20 22 28 24 [0-20] 29 29 2c 20 24 [0-20] 29 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = "( \"A\" & \"s\" & \"c\" & \"(\" & \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d\" &" ascii //weight: 1
        $x_1_6 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SYHZ_2147938557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SYHZ!MTB"
        threat_id = "2147938557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_5_2 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 41 00 73 00 63 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_3 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-20] 20 28 20 22 41 73 63 22 20 2c 20 24 [0-20] 20 28 20 22 53 74 72 69 6e 67 4d 69 64 22 20 2c 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 5, accuracy: Low
        $x_6_4 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 6, accuracy: Low
        $x_6_5 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 6, accuracy: Low
        $x_1_6 = "EXECUTE ( \"C\" & \"al\" & \"l\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*))) or
            ((2 of ($x_6_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SR_2147942456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SR!MTB"
        threat_id = "2147942456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DLLCALL ( BINARYTOSTRING ( \"0x6B65726E656C33322E646C6C\" ) , BINARYTOSTRING ( \"0x68616E646C65\" )" ascii //weight: 1
        $x_1_2 = "DLLCALL ( BINARYTOSTRING ( \"0x7573657233322E646C6C\" ) ," ascii //weight: 1
        $x_2_3 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 36 00 32 00 37 00 39 00 37 00 34 00 36 00 35 00 35 00 42 00 22 00 20 00 29 00 20 00 26 00 20 00 24 00 [0-50] 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 35 00 44 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 42 49 4e 41 52 59 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 36 32 37 39 37 34 36 35 35 42 22 20 29 20 26 20 24 [0-50] 20 26 20 42 49 4e 41 52 59 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 35 44 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = "DLLOPEN ( BINARYTOSTRING ( \"0x7573657233322E646C6C\" ) )" ascii //weight: 2
        $x_1_6 = "IF @ERROR THEN RETURN SETERROR ( @ERROR , @EXTENDED , FALSE )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SPJ_2147943939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPJ!MTB"
        threat_id = "2147943939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-32] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-32] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-32] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 2c 00 20 00 [0-32] 20 00 28 00 20 00 22 00 31 00 30 00 39 00 20 00 31 00 33 00 32 00 20 00 31 00 32 00 37 00 20 00 31 00 31 00 32 00 20 00 31 00 30 00 32 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-32] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {28 20 22 44 6c 6c 53 74 72 75 63 74 43 72 65 61 74 65 22 20 2c 20 [0-32] 20 28 20 22 31 30 39 20 31 33 32 20 31 32 37 20 31 31 32 20 31 30 32 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-32] 20 29}  //weight: 1, accuracy: Low
        $x_2_5 = {28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 53 00 65 00 74 00 44 00 61 00 74 00 61 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {28 20 22 44 6c 6c 53 74 72 75 63 74 53 65 74 44 61 74 61 22 20 2c 20 24 [0-32] 20 2c 20 31 20 2c 20 24 [0-32] 20 29}  //weight: 2, accuracy: Low
        $x_2_7 = {28 00 20 00 22 00 37 00 39 00 20 00 31 00 31 00 39 00 20 00 31 00 31 00 39 00 20 00 37 00 38 00 20 00 31 00 30 00 38 00 20 00 31 00 31 00 39 00 20 00 31 00 31 00 39 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-32] 20 00 28 00 20 00 22 00 31 00 31 00 38 00 20 00 31 00 31 00 32 00 20 00 31 00 32 00 35 00 20 00 31 00 32 00 31 00 20 00 31 00 31 00 32 00 20 00 31 00 31 00 39 00 20 00 36 00 32 00 20 00 36 00 31 00 20 00 35 00 37 00 20 00 31 00 31 00 31 00 20 00 31 00 31 00 39 00 20 00 31 00 31 00 39 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_8 = {28 20 22 37 39 20 31 31 39 20 31 31 39 20 37 38 20 31 30 38 20 31 31 39 20 31 31 39 22 20 29 20 2c 20 [0-32] 20 28 20 22 31 31 38 20 31 31 32 20 31 32 35 20 31 32 31 20 31 31 32 20 31 31 39 20 36 32 20 36 31 20 35 37 20 31 31 31 20 31 31 39 20 31 31 39 22 20 29}  //weight: 2, accuracy: Low
        $x_1_9 = {28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 53 00 70 00 6c 00 69 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 22 00 27 00 20 00 26 00 20 00 27 00 20 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {28 20 22 53 74 72 69 6e 22 20 26 20 22 67 53 70 6c 69 74 22 20 2c 20 24 [0-32] 20 2c 20 22 27 20 26 20 27 20 22 20 2c 20 32 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SPM_2147944263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SPM!MTB"
        threat_id = "2147944263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE ( \"Call\" )" ascii //weight: 1
        $x_1_2 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_2_4 = {28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 53 00 70 00 6c 00 69 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 22 00 27 00 20 00 26 00 20 00 27 00 20 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_5 = {28 20 22 53 74 72 69 6e 22 20 26 20 22 67 53 70 6c 69 74 22 20 2c 20 24 [0-20] 20 2c 20 22 27 20 26 20 27 20 22 20 2c 20 32 20 29}  //weight: 2, accuracy: Low
        $x_2_6 = "PIXELCHECKSUM ( 145 , 686 , 399 , 332 , 557 )" ascii //weight: 2
        $x_1_7 = {28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 49 00 6e 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 5b 00 20 00 24 00 [0-20] 20 00 5d 00 20 00 29 00 20 00 2b 00 20 00 2d 00 31 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {28 20 22 43 22 20 26 20 22 68 72 22 20 2c 20 24 [0-20] 20 28 20 22 49 6e 74 22 20 2c 20 24 [0-20] 20 5b 20 24 [0-20] 20 5d 20 29 20 2b 20 2d 31 31 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 39 00 20 00 31 00 33 00 32 00 20 00 31 00 32 00 37 00 22 00 20 00 26 00 20 00 22 00 20 00 31 00 31 00 32 00 20 00 31 00 30 00 32 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {28 20 22 44 6c 6c 53 74 72 75 63 74 43 72 65 61 74 65 22 20 2c 20 [0-20] 20 28 20 22 31 30 39 20 31 33 32 20 31 32 37 22 20 26 20 22 20 31 31 32 20 31 30 32 22 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 53 00 65 00 74 00 44 00 61 00 74 00 61 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {28 20 22 44 6c 6c 53 74 72 75 63 74 53 65 74 44 61 74 61 22 20 2c 20 24 [0-20] 20 2c 20 31 20 2c 20 24 [0-20] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autoitinject_SDS_2147945220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinject.SDS!MTB"
        threat_id = "2147945220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 00 20 00 22 00 4d 00 6f 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {28 20 22 4d 6f 64 22 20 2c 20 24 [0-20] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {28 20 22 43 68 72 22 20 2c 20 24 [0-20] 20 28 20 22 42 69 74 58 4f 52 22 20 2c 20 24 [0-20] 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 2, accuracy: Low
        $x_1_7 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 44 45 4c 45 54 45 20 28 20 22 64 65 66 61 75 6c 74 22 20 2c 20 24 [0-20] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

