rule Trojan_Win64_AVTamper_B_2147836774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AVTamper.B"
        threat_id = "2147836774"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AVTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[-] StopDefenderServices Error: %i" ascii //weight: 2
        $x_1_2 = "[-] ImpersonatedLoggedOnUser() Error: %i" ascii //weight: 1
        $x_1_3 = "[-] WINLOGON ImpersonatedLoggedOnUser() Return Code: %i" ascii //weight: 1
        $x_2_4 = "[+] TRUSTEDINSTALLER StopDefenderService() success!" ascii //weight: 2
        $x_2_5 = "[-] StopDefenderServices() Error: %i" ascii //weight: 2
        $x_1_6 = "[-] %s ImpersonatedLoggedOnUser() Return Code: %i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_AVTamper_C_2147903961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AVTamper.C"
        threat_id = "2147903961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AVTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 72 6e 65 6c 62 61 73 65 2e 64 6c 6c 00 5c 5c 2e 5c 61 6d 73 64 6b 00 61 63 74 69 76 65 63 6f 6e 73 6f 6c 65 00 61 6e 74 69 20 6d 61 6c 77 61 72 65}  //weight: 1, accuracy: High
        $x_1_2 = {63 73 66 61 6c 63 6f 6e 00 63 73 73 68 65 6c 6c 00 63 79 62 65 72 65 61 73 6f 6e 00 63 79 63 6c 6f 72 61 6d 61 00 63 79 6c 61 6e 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AVTamper_D_2147904757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AVTamper.D!ldr"
        threat_id = "2147904757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AVTamper"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 61 69 6c 65 64 21 0a 00 65 72 ?? 6f 72 20 25 64 0a 00 42 49 4e 41 52 59 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

