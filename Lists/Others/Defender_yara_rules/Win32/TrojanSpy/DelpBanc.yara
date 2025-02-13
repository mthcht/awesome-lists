rule TrojanSpy_Win32_DelpBanc_A_2147597752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/DelpBanc.A"
        threat_id = "2147597752"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "DelpBanc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rfkindysadvnqw3nerasdf" ascii //weight: 3
        $x_1_2 = "Content-Type: multipart/alternative;" ascii //weight: 1
        $x_1_3 = "primeira_serie" ascii //weight: 1
        $x_1_4 = "segunda_serie" ascii //weight: 1
        $x_1_5 = "terceira_serie" ascii //weight: 1
        $x_1_6 = "quarta_serie" ascii //weight: 1
        $x_3_7 = "Portal Banco Real" ascii //weight: 3
        $x_3_8 = "senhacartao" ascii //weight: 3
        $x_2_9 = "Adobe Photoshop 7." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

