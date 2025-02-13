rule Trojan_Win32_Cendelf_A_2147682393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cendelf.gen!A"
        threat_id = "2147682393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cendelf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {69 65 74 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c}  //weight: 4, accuracy: High
        $x_1_2 = {81 ff 91 68 84 25 75}  //weight: 1, accuracy: High
        $x_1_3 = {81 fe 24 74 98 26 75}  //weight: 1, accuracy: High
        $x_1_4 = {81 7d 08 24 74 98 26 75}  //weight: 1, accuracy: High
        $x_1_5 = {81 7d 08 91 68 84 25 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

