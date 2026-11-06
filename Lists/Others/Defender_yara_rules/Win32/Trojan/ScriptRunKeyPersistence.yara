rule Trojan_Win32_ScriptRunKeyPersistence_A_2147981694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScriptRunKeyPersistence.A"
        threat_id = "2147981694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScriptRunKeyPersistence"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg" wide //weight: 1
        $x_1_2 = " add " wide //weight: 1
        $x_1_3 = "\\software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
        $x_1_4 = "/d" wide //weight: 1
        $x_1_5 = "wscript" wide //weight: 1
        $x_1_6 = ".vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

