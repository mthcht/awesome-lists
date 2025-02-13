rule Trojan_Win32_Scrwban_A_2147841351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scrwban.A!dha"
        threat_id = "2147841351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrwban"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download?cid=4BFA286866B1C02A&resid=4BFA286866B1C02A%21105&authkey=ALs3JGaXia7oul4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

