rule PWS_Win32_Delfsnif_G_2147596361_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delfsnif.gen!G"
        threat_id = "2147596361"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6e 64 3b 6d 65 6e 61 6d 65 65 78 65 3a 00 00 ff ff ff ff 0e 00 00 00 65 6e 64 3b 6d 65 6e 61}  //weight: 1, accuracy: High
        $x_1_2 = {3b 6d 65 6e 61 6d 65 64 6c 6c 3a 00 00 ff ff ff ff 0b 00 00 00 65 6e 64 3b 73 78 70 6f 72 74 3a}  //weight: 1, accuracy: High
        $x_1_3 = {63 6d 64 2e 65 78 65 00 55 8b ec 33 c0 55 68 ?? ?? 41 00 64 ff 30 64 89 20 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Delfsnif_H_2147596385_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delfsnif.gen!H"
        threat_id = "2147596385"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nameexe:" ascii //weight: 1
        $x_1_2 = {70 61 73 73 3a 00 00 00}  //weight: 1, accuracy: High
        $x_3_3 = "if exist" ascii //weight: 3
        $x_3_4 = "about:blank" ascii //weight: 3
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_3_6 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 3
        $x_3_7 = "Generic Host Process for Win32 Services" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

