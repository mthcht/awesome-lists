rule TrojanClicker_Win32_Lochob_A_2147665970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Lochob.A"
        threat_id = "2147665970"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Lochob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 75 fc cc f1 b3 a0}  //weight: 2, accuracy: High
        $x_1_2 = "coon_advise" ascii //weight: 1
        $x_1_3 = "r_bho_mtx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

