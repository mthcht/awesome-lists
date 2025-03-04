rule Trojan_Win64_ReedBed_A_2147927914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReedBed.A"
        threat_id = "2147927914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReedBed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HookNtCreateUserProcess(): ok!" ascii //weight: 1
        $x_1_2 = "HookRtlExitUserProcess(): RtlExitUserProcess not found hNtdll=%#p" ascii //weight: 1
        $x_1_3 = "\\bc_ssl_client." ascii //weight: 1
        $x_1_4 = "send_pipe_ssl(): SSL_write(): SSL_ERROR_WANT_WRITE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_ReedBed_B_2147927915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReedBed.B!ldr"
        threat_id = "2147927915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReedBed"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 71 30 41 bf 01 00 00 ?? 4c 23 f0 48 03 d9 45 2b e7 44 8b 5b 20 41 f7 d4 4c 8d 43 18 4d 0b de 48 8b f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReedBed_AL_2147933585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReedBed.AL!MTB"
        threat_id = "2147933585"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReedBed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b d1 8b ca 48 63 c9 48 0f af c1 0f b6 44 04 ?? 8b 8c 24 ?? 00 00 00 33 c8 8b c1 48 63 4c 24 ?? 48 8b 94 24 ?? 00 00 00 88 04 0a e9}  //weight: 3, accuracy: Low
        $x_2_2 = {33 d2 48 8b c1 b9 ?? 00 00 00 48 f7 f1 48 8b c2 b9 01 00 00 00 48 6b c9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ReedBed_DA_2147933970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReedBed.DA!MTB"
        threat_id = "2147933970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReedBed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 2b c8 49 0f af cf 0f b6 44 ?? ?? 41 32 44 ?? fc 41 88 40 ff 49 ff cc 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {48 2b c8 49 0f af cf 0f b6 44 ?? ?? 42 32 44 ?? fc 41 88 40 ff 49 ff cc 0f 85}  //weight: 10, accuracy: Low
        $x_10_3 = {48 2b c8 49 0f af cf 0f b6 44 ?? ?? 43 32 44 ?? fc 41 88 40 ff 49 ff cc 0f 85}  //weight: 10, accuracy: Low
        $x_1_4 = {48 63 c8 48 8b c3 48 f7 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ReedBed_H_2147935144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReedBed.H"
        threat_id = "2147935144"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReedBed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 74 43 72 65 61 74 65 55 73 65 72 50 72 6f 63 65 73 73 00 00 00 00 ?? 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 00 00 00 00 00 00 00 00 55 00 53 00 45 00 52 00 44 00 4f 00 4d 00 41 00 49 00 4e 00 00 00 00 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b cf 8b d0 80 39 42 75 ?? c6 01 2e 48 ff c1 48 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

