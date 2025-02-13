rule Trojan_Win32_Valcailoz_A_2147716302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valcailoz.A"
        threat_id = "2147716302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valcailoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = ".zolcai.com/gow.php" wide //weight: 4
        $x_1_2 = "comelook.zolcai.com" wide //weight: 1
        $x_1_3 = "ent.zolcai.com" wide //weight: 1
        $x_1_4 = "kango.zolcai." wide //weight: 1
        $x_1_5 = "cai.geduo.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

