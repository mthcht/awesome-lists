rule Trojan_Win32_TrickySpeller_A_2147773775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickySpeller.A!dha"
        threat_id = "2147773775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickySpeller"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "$t = '';for($i=0;$i -lt $a.Length;$i+=3)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

