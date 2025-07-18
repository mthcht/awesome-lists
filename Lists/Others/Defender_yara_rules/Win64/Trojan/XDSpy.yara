rule Trojan_Win64_XDSpy_GVA_2147946839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XDSpy.GVA!MTB"
        threat_id = "2147946839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XDSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "officeupdtcentr.com" ascii //weight: 2
        $x_2_2 = "seatwowave.com" ascii //weight: 2
        $x_1_3 = "cmd.exe /u /c cd /d \"%s\" & dir /a /-c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

