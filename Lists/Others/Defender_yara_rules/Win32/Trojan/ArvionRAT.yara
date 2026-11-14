rule Trojan_Win32_ArvionRAT_2147982147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArvionRAT!atmn"
        threat_id = "2147982147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArvionRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ARVPACK01:C1D000P1V1G1M0J0" ascii //weight: 3
        $x_3_2 = "ARVNAME01:SpeechRuntime" ascii //weight: 3
        $x_3_3 = "ARVION_PROFILE" ascii //weight: 3
        $x_2_4 = "CFG_SLOT_A:bot_linux_x86_64" ascii //weight: 2
        $x_3_5 = "narvion.stop" wide //weight: 3
        $x_2_6 = "arv_boot.txt" wide //weight: 2
        $x_2_7 = "stage_http_ok host=%s st=%lu bytes=%u" ascii //weight: 2
        $x_2_8 = "stage_fetch" ascii //weight: 2
        $x_2_9 = "ov_magic_no" ascii //weight: 2
        $x_1_10 = "ov_chunk" ascii //weight: 1
        $x_1_11 = "kill_wdskip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

