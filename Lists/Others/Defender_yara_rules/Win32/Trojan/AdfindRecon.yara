rule Trojan_Win32_AdfindRecon_C_2147782851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AdfindRecon.C!ibt"
        threat_id = "2147782851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AdfindRecon"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe /c adfind.exe" wide //weight: 10
        $x_5_2 = "-f objectcategory=computer -csv name cn operatingsystem dnshostname" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

