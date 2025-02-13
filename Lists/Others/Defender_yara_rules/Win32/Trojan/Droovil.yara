rule Trojan_Win32_Droovil_A_2147811724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Droovil.A!dha"
        threat_id = "2147811724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Droovil"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vlak2%x" ascii //weight: 1
        $x_1_2 = {63 6d 64 2e 65 78 65 00 50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: High
        $x_1_3 = {69 64 3d 00 25 30 33 78 00 00 00 00 26 75 72 69 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

