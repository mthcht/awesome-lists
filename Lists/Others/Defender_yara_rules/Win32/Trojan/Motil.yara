rule Trojan_Win32_Motil_A_2147826891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Motil.A!MTB"
        threat_id = "2147826891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Motil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMMOUSE\\VB\\blacklist\\blacklist.exe" wide //weight: 1
        $x_1_2 = "r7gGHG6MhUtcRRhBneO0QDWXCCygYt" wide //weight: 1
        $x_1_3 = "8gVZwjQrIukHhtDwcOdCD6nwFD6XNAqTq7qDpzWZ+87YEpWDR5imw0+NTg5fmiPw==" wide //weight: 1
        $x_1_4 = "Strip Restrictions" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

