rule Trojan_Win32_AutoitLodaRat_RA_2147847381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitLodaRat.RA!MTB"
        threat_id = "2147847381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitLodaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FILEINSTALL ( \"C:\\Users\\dell\\Desktop\\S500- payloaders\\Maining.exe\" , @TEMPDIR" ascii //weight: 2
        $x_1_2 = "SHELLEXECUTE ( @TEMPDIR &" ascii //weight: 1
        $x_1_3 = "&= CHR ( BITXOR" ascii //weight: 1
        $x_1_4 = "> 600000 THEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

