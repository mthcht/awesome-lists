rule Trojan_Win64_MangoJuice_A_2147959132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MangoJuice.A!dha"
        threat_id = "2147959132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MangoJuice"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".?AVMyCMDManager@@" ascii //weight: 1
        $x_1_2 = ".?AVTCPNetBufferHelper@@" ascii //weight: 1
        $x_1_3 = ".?AVNetBufferHelper@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

