rule Trojan_Win64_Redcap_SPQ_2147845434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.SPQ!MTB"
        threat_id = "2147845434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Boisgioesgjesgg" ascii //weight: 1
        $x_1_2 = "Oioagjiosejghe" ascii //weight: 1
        $x_1_3 = "Uioesoigseighsehji" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_GMK_2147892320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.GMK!MTB"
        threat_id = "2147892320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qedis_mbulk_reply_zipped_keys_dbl" ascii //weight: 1
        $x_1_2 = "php_redis.dll" ascii //weight: 1
        $x_1_3 = "qluster_mbulk_zipstr_resp" ascii //weight: 1
        $x_1_4 = "qedis_sock_connect" ascii //weight: 1
        $x_1_5 = "qedis_pool_get_sock" ascii //weight: 1
        $x_1_6 = "qluster_gen_mbulk_resp" ascii //weight: 1
        $x_1_7 = "qedis_sock_read_multibulk_multi_reply_loop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_ASG_2147894260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.ASG!MTB"
        threat_id = "2147894260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 f7 f1 48 8b c2 48 8b 8c 24 f8 00 00 00 0f b6 04 01 48 8b 4c 24 28 48 8b 94 24 00 01 00 00 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 28 48 8b 54 24 38 48 03 d1 48 8b ca 88 01 eb}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 44 24 48 48 8b 44 24 30 8b 40 50 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 ff 54 24 48}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_AMBA_2147895925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.AMBA!MTB"
        threat_id = "2147895925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 02 d9 44 02 df 41 0f b6 cb 0f b6 44 8d 08 41 30 46 ff 8b 44 8d 08 31 44 95 08 42 8b 44 a5 08 41 8d 0c 00 42 31 4c 95 08 49 ff cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_NR_2147899136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.NR!MTB"
        threat_id = "2147899136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 3d 78 5e 0a 00 44 8b 0f 45 85 c9 0f 85 ac 02 00 00 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 1d ac 5d 0a 00 48 8b 70 08 31 ed}  //weight: 3, accuracy: Low
        $x_3_2 = {75 e2 48 8b 35 ?? ?? ?? ?? 31 ed 8b 06 83 f8 ?? 0f 84 13 02 00 00 8b 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_NR_2147899136_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.NR!MTB"
        threat_id = "2147899136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\malware\\Black-Angel-Rootkit\\x64\\Release\\Black Angel Client.pdb" ascii //weight: 1
        $x_1_2 = "Hide Process" ascii //weight: 1
        $x_1_3 = "Elevate Process" ascii //weight: 1
        $x_1_4 = "Protect Process" ascii //weight: 1
        $x_1_5 = "Hide Directory" ascii //weight: 1
        $x_1_6 = "Hide Port" ascii //weight: 1
        $x_1_7 = "Hide Registry Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_APC_2147918689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.APC!MTB"
        threat_id = "2147918689"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "parsexxxxx.text" ascii //weight: 1
        $x_1_2 = ", hostname: %v, elevated: " ascii //weight: 1
        $x_1_3 = "Payload(%v) active, connecting to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_YAA_2147925420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.YAA!MTB"
        threat_id = "2147925420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Fake RTL_BITMAP allocated at address = %" ascii //weight: 10
        $x_1_2 = "leak_gadget_address failed" ascii //weight: 1
        $x_1_3 = "KsOpenDefaultDevice at index %d failed with error = %x" ascii //weight: 1
        $x_1_4 = "Calling Write64 wrapper to overwrite current EPROCESS->Token" ascii //weight: 1
        $x_1_5 = "Leveraging DKOM to achieve LPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_KGF_2147925764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.KGF!MTB"
        threat_id = "2147925764"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 0f b6 44 0c 20 43 32 04 0a 41 88 01}  //weight: 2, accuracy: High
        $x_1_2 = "D^Gws*f!8wENr9d%I#^RMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_MBWB_2147926742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.MBWB!MTB"
        threat_id = "2147926742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 e1 c1 07 e6 d6 18 e6 70 61 74 68 09 63 6f 6d 6d 61 6e 64 2d 6c 69 6e 65 2d 61 72 67 75 6d 65 6e 74 73 0a 64 65 70 09 67 69 74 68 75 62 2e 63 6f 6d 2f 6d 69 74 72 65 2f 6d 61 6e 78 2f 73 68 65 6c 6c 73 09 28 64 65 76 65 6c 29 09 0a 62 75 69 6c 64}  //weight: 10, accuracy: High
        $x_1_2 = "6gEDx5VIQ_T88vM7IzkT/cS" ascii //weight: 1
        $x_1_3 = "d-Xg8Lhe25ACNP-V9yIO/9g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Redcap_ARDP_2147933485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.ARDP!MTB"
        threat_id = "2147933485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 38 48 89 44 24 48 48 8b 10 48 89 54 24 40 48 8b 58 08 48 89 5c 24 30 48 8d 0d ?? ?? 1e 00 bf 0b 00 00 00 48 89 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_AB_2147945993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.AB!MTB"
        threat_id = "2147945993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c9 eb 07 48 81 c1 60 98 00 00 48 81 f9 5f 98 00 00 7c f0 31 c9 eb 07 48 81 c1 30 34 00 00 48 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redcap_GZF_2147952062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redcap.GZF!MTB"
        threat_id = "2147952062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 0f b6 05 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8b 54 24 40 48 03 d1 48 8b ca 0f b6 09 03 c8 8b c1 48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

