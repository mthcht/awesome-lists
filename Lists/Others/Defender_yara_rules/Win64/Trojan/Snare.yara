rule Trojan_Win64_Snare_S_2147745631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Snare.S!MSR"
        threat_id = "2147745631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Snare"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CSHMDR" wide //weight: 1
        $x_1_2 = "O3dJxbOYd3Y2RhQJOIJ/d0r=" ascii //weight: 1
        $x_1_3 = "ANONYMOUS LOGON" ascii //weight: 1
        $x_1_4 = "atlTraceCOM" wide //weight: 1
        $x_1_5 = "atlTraceWindowing" wide //weight: 1
        $x_1_6 = "NetUserGetInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

