rule Trojan_Win32_Bodixm_A_2147725705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bodixm.A!bit"
        threat_id = "2147725705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodixm"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{RC58-XM4I-K5DI-MW48-2CB8-O4QQ}" wide //weight: 1
        $x_1_2 = "ping -n 3 localhost & schtasks /create /tn " wide //weight: 1
        $x_1_3 = "\\patch\\ntd2.dll" wide //weight: 1
        $x_1_4 = "\\patch\\krn.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

