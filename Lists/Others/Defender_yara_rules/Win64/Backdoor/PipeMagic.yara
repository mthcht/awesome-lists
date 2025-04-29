rule Backdoor_Win64_PipeMagic_D_2147940252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PipeMagic.D!ldr"
        threat_id = "2147940252"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PipeMagic"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 08 41 30 14 08 48 8d 51 01 48 89 d1 48 83 fa 10 75}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e6 18 c1 e7 10 41 c1 e3 08 41 09 cb 41 09 fb 48 89 df 41 09 f3 41 8b 48 ?? 0f c9 44 31 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_PipeMagic_E_2147940253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PipeMagic.E"
        threat_id = "2147940253"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PipeMagic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 03 d0 c1 fa 07 8b ca c1 e9 1f 03 d1 69 ca ff 00 00 ?? 44 2b c1 44 88 04 03 48 03 df 48 83 fb 10}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 00 49 ff c0 8b c8 48 c1 e8 04 83 e1 0f 42 8a 04 18 88 02 48 8d 52 02 42 8a 04 19 88 42 ff 41 83 c1 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

