rule Trojan_Win32_SourBack_A_2147773980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SourBack.A!dha"
        threat_id = "2147773980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SourBack"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "uplphostsvc.net" ascii //weight: 3
        $x_1_2 = "Software\\Microsoft\\Windows NT\\Currentversion" ascii //weight: 1
        $x_1_3 = "%d/%d/%d %d:%d" ascii //weight: 1
        $x_1_4 = {2f 49 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {80 00 24 40 80 38 00 75 f7}  //weight: 1, accuracy: High
        $x_1_6 = {04 24 8d 49 01 88 41 ff 8a 01 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

