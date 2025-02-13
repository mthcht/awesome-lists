rule Trojan_WinNT_Eqtonex_C_2147726378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Eqtonex.C"
        threat_id = "2147726378"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ee ff c0 d0}  //weight: 1, accuracy: High
        $x_1_2 = {ef be 00 d0}  //weight: 1, accuracy: High
        $x_1_3 = "ntevt.sys" ascii //weight: 1
        $x_1_4 = "\\??\\C:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

