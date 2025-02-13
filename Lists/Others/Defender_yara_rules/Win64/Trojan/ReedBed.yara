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

