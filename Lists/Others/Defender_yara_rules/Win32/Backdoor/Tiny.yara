rule Backdoor_Win32_Tiny_AAA_2147970529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tiny.AAA!AMTB"
        threat_id = "2147970529"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "shttp://free-steal.ru/ucp/include/70SM78F1dkhji.php" wide //weight: 10
        $x_2_2 = "%ws%s:%d=%s=%s=%d=%s=%s" ascii //weight: 2
        $x_2_3 = "%ws%s:%d=%s=%s=%d=%ws=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

